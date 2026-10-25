package breaker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type SessionState struct {
	SessionID         string
	TotalCostUSD      float64
	TotalCalls        int
	LastFingerprint   string
	IdenticalCount    int
	CacheMissStreak   int
	TrippedCount      int
	LastUpdatedAt     time.Time
}

type Breaker struct {
	mu                  sync.Mutex
	maxSessionCostUSD   float64
	maxDailyCostUSD     float64
	maxIdenticalRetries int
	dailyCostUSD        float64
	dailyDay            string
	sessions            map[string]*SessionState
}

type CheckResult struct {
	Allowed       bool
	Reason        string
	Code          string // "OK", "DOOM_LOOP_DETECTED", "SESSION_BUDGET_EXCEEDED", "DAILY_BUDGET_EXCEEDED"
	SessionCost   float64
	IdenticalHits int
}

func New(maxSessionCost, maxDailyCost float64, maxRetries int) *Breaker {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &Breaker{
		maxSessionCostUSD:   maxSessionCost,
		maxDailyCostUSD:     maxDailyCost,
		maxIdenticalRetries: maxRetries,
		dailyDay:            time.Now().UTC().Format("2006-01-02"),
		sessions:            make(map[string]*SessionState),
	}
}

// ComputeFingerprint extracts the tail of the prompt (last tool output / user message)
// and normalizes whitespace so repeated identical agent errors hash to the same digest.
func ComputeFingerprint(payload string) string {
	norm := strings.TrimSpace(payload)
	if len(norm) > 2048 {
		norm = norm[len(norm)-2048:]
	}
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:8])
}

func (b *Breaker) EvaluatePreCall(sessionID, payload string, estCostUSD float64) CheckResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	today := time.Now().UTC().Format("2006-01-02")
	if b.dailyDay != today {
		b.dailyDay = today
		b.dailyCostUSD = 0
	}

	if sessionID == "" {
		sessionID = "default-session"
	}
	st, ok := b.sessions[sessionID]
	if !ok {
		st = &SessionState{SessionID: sessionID}
		b.sessions[sessionID] = st
	}
	st.LastUpdatedAt = time.Now()

	fp := ComputeFingerprint(payload)
	if fp == st.LastFingerprint && fp != "" {
		st.IdenticalCount++
	} else {
		st.LastFingerprint = fp
		st.IdenticalCount = 1
	}

	// 1. Check Doom-Loop (Identical consecutive payloads/errors)
	if st.IdenticalCount > b.maxIdenticalRetries {
		st.TrippedCount++
		return CheckResult{
			Allowed:       false,
			Code:          "DOOM_LOOP_DETECTED",
			Reason:        fmt.Sprintf("Agent sent identical request/error %d times consecutively (limit: %d). Halting runaway loop.", st.IdenticalCount, b.maxIdenticalRetries),
			SessionCost:   st.TotalCostUSD,
			IdenticalHits: st.IdenticalCount,
		}
	}

	// 2. Check Session Budget Cap
	if b.maxSessionCostUSD > 0 && (st.TotalCostUSD+estCostUSD) > b.maxSessionCostUSD {
		st.TrippedCount++
		return CheckResult{
			Allowed:       false,
			Code:          "SESSION_BUDGET_EXCEEDED",
			Reason:        fmt.Sprintf("Session %q reached cost cap ($%.4f / $%.2f limit).", sessionID, st.TotalCostUSD+estCostUSD, b.maxSessionCostUSD),
			SessionCost:   st.TotalCostUSD,
			IdenticalHits: st.IdenticalCount,
		}
	}

	// 3. Check Daily Budget Cap
	if b.maxDailyCostUSD > 0 && (b.dailyCostUSD+estCostUSD) > b.maxDailyCostUSD {
		st.TrippedCount++
		return CheckResult{
			Allowed:       false,
			Code:          "DAILY_BUDGET_EXCEEDED",
			Reason:        fmt.Sprintf("Daily spend cap reached ($%.4f / $%.2f limit).", b.dailyCostUSD+estCostUSD, b.maxDailyCostUSD),
			SessionCost:   st.TotalCostUSD,
			IdenticalHits: st.IdenticalCount,
		}
	}

	st.TotalCalls++
	st.TotalCostUSD += estCostUSD
	b.dailyCostUSD += estCostUSD

	return CheckResult{
		Allowed:       true,
		Code:          "OK",
		SessionCost:   st.TotalCostUSD,
		IdenticalHits: st.IdenticalCount,
	}
}

// EvaluateCacheChurn inspects post-call cache_creation_input_tokens vs cache_read_input_tokens.
// If a session repeatedly writes large caches without reading them (Cache Busting / Silent Creep),
// it flags a Cache Churn Alert and returns the wasted USD compared to a cache hit.
func (b *Breaker) EvaluateCacheChurn(sessionID string, cacheReadTokens, cacheWriteTokens, uncachedInTokens int, inRatePerM float64) (bool, float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sessionID == "" {
		sessionID = "default-session"
	}
	st, ok := b.sessions[sessionID]
	if !ok {
		st = &SessionState{SessionID: sessionID}
		b.sessions[sessionID] = st
	}

	totalContext := cacheReadTokens + cacheWriteTokens + uncachedInTokens
	if totalContext < 500 {
		return false, 0
	}

	// If cacheWrite + uncachedIn dominates (>70% of context) after the first turn in a session,
	// the agent is busting the prompt cache on every turn.
	hitRatio := float64(cacheReadTokens) / float64(totalContext)
	if st.TotalCalls > 1 && hitRatio < 0.30 && (cacheWriteTokens > 0 || uncachedInTokens > 1000) {
		st.CacheMissStreak++
		// Calculate wasted USD: Cache Write costs 1.25x base rate, whereas Cache Read costs 0.10x base rate.
		rebuiltTokens := cacheWriteTokens + uncachedInTokens
		wastedUSD := (float64(rebuiltTokens) / 1_000_000.0) * (inRatePerM * 1.15)
		return true, wastedUSD
	}

	st.CacheMissStreak = 0
	return false, 0
}
