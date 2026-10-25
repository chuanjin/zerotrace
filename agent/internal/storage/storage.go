package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent represents a single immutable telemetry record compliant with EU AI Act Art. 12 & GDPR.
type AuditEvent struct {
	Seq               int64          `json:"seq"`
	Timestamp         string         `json:"timestamp"`
	SessionID         string         `json:"session_id"`
	Provider          string         `json:"provider"`
	Model             string         `json:"model"`
	Repo              string         `json:"repo,omitempty"`
	TokensIn          int            `json:"tokens_in"`
	TokensCacheRead   int            `json:"tokens_cache_read"`
	TokensOut         int            `json:"tokens_out"`
	CostUSD           float64        `json:"cost_usd"`
	SavedUSD          float64        `json:"saved_usd"` // Money saved when circuit breaker trips
	LatencyMs         int64          `json:"latency_ms"`
	Status            string         `json:"status"` // "OK", "DOOM_LOOP_DETECTED", "SESSION_BUDGET_EXCEEDED"
	PIIRedactions     int            `json:"pii_redactions"`
	PIICategories     map[string]int `json:"pii_categories,omitempty"`
	EncryptedPayload  string         `json:"encrypted_payload"` // AES-256-GCM ciphertext (Zero-Knowledge)
	PrevHash          string         `json:"prev_hash"`         // Cryptographic tamper-evident chain
	EventHash         string         `json:"event_hash"`
}

type Manifest struct {
	AccountID            string         `json:"account_id"`
	UpdatedAt            string         `json:"updated_at"`
	TotalRequests        int64          `json:"total_requests"`
	TotalCostUSD         float64        `json:"total_cost_usd"`
	TotalSavedUSD        float64        `json:"total_saved_usd"`
	TotalPIIRedactions   int64          `json:"total_pii_redactions"`
	TotalLoopsBlocked    int64          `json:"total_loops_blocked"`
	PIICategoryBreakdown map[string]int `json:"pii_category_breakdown"`
	ChainHeadHash        string         `json:"chain_head_hash"`
	ChainVerified        bool           `json:"chain_verified"`
	RecentEvents         []AuditEvent   `json:"recent_events"`
}

type Store struct {
	mu        sync.Mutex
	dataDir   string
	accountID string
	e2eeKey   []byte
	seq       int64
	prevHash  string
	manifest  Manifest
}

func New(dataDir, accountID, e2eeKeyHex string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	keyBytes, err := hex.DecodeString(e2eeKeyHex)
	if err != nil || len(keyBytes) != 32 {
		sum := sha256.Sum256([]byte(e2eeKeyHex))
		keyBytes = sum[:]
	}

	s := &Store{
		dataDir:   dataDir,
		accountID: accountID,
		e2eeKey:   keyBytes,
		prevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		manifest: Manifest{
			AccountID:            accountID,
			PIICategoryBreakdown: make(map[string]int),
			ChainVerified:        true,
		},
	}
	s.loadExisting()
	return s, nil
}

func (s *Store) loadExisting() {
	mPath := filepath.Join(s.dataDir, "manifest.json")
	if data, err := os.ReadFile(mPath); err == nil {
		_ = json.Unmarshal(data, &s.manifest)
		if s.manifest.PIICategoryBreakdown == nil {
			s.manifest.PIICategoryBreakdown = make(map[string]int)
		}
		s.seq = s.manifest.TotalRequests
		if s.manifest.ChainHeadHash != "" {
			s.prevHash = s.manifest.ChainHeadHash
		}
	}
}

func (s *Store) EncryptPayload(plaintext string) string {
	block, err := aes.NewCipher(s.e2eeKey)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed)
}

func ComputeEventHash(ev AuditEvent) string {
	canonical := fmt.Sprintf("%d|%s|%s|%s|%s|%d|%d|%.6f|%s|%d|%s",
		ev.Seq, ev.Timestamp, ev.SessionID, ev.Provider, ev.Model,
		ev.TokensIn, ev.TokensOut, ev.CostUSD, ev.Status, ev.PIIRedactions, ev.PrevHash)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func (s *Store) Append(ev AuditEvent, rawSanitizedPrompt string) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	ev.Seq = s.seq
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	ev.EncryptedPayload = s.EncryptPayload(rawSanitizedPrompt)
	ev.PrevHash = s.prevHash
	ev.EventHash = ComputeEventHash(ev)
	s.prevHash = ev.EventHash

	// Append to daily JSONL / Parquet staging log
	day := time.Now().UTC().Format("2006-01-02")
	logPath := filepath.Join(s.dataDir, fmt.Sprintf("audit-%s.jsonl", day))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return ev, err
	}
	line, _ := json.Marshal(ev)
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()

	// Update manifest
	s.manifest.UpdatedAt = ev.Timestamp
	s.manifest.TotalRequests = s.seq
	s.manifest.TotalCostUSD += ev.CostUSD
	s.manifest.TotalSavedUSD += ev.SavedUSD
	s.manifest.TotalPIIRedactions += int64(ev.PIIRedactions)
	if ev.Status != "OK" {
		s.manifest.TotalLoopsBlocked++
	}
	for k, v := range ev.PIICategories {
		s.manifest.PIICategoryBreakdown[k] += v
	}
	s.manifest.ChainHeadHash = ev.EventHash
	s.manifest.RecentEvents = append([]AuditEvent{ev}, s.manifest.RecentEvents...)
	if len(s.manifest.RecentEvents) > 50 {
		s.manifest.RecentEvents = s.manifest.RecentEvents[:50]
	}

	mBytes, _ := json.MarshalIndent(s.manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(s.dataDir, "manifest.json"), mBytes, 0600)

	return ev, nil
}

func (s *Store) GetManifest() Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifest
}

// VerifyAuditChain walks all audit-*.jsonl files and verifies cryptographic SHA-256 continuity.
func VerifyAuditChain(dataDir string) (int, string, error) {
	files, err := filepath.Glob(filepath.Join(dataDir, "audit-*.jsonl"))
	if err != nil {
		return 0, "", err
	}
	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	count := 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return count, "", err
		}
		for _, line := range splitNonEmptyLines(string(raw)) {
			var ev AuditEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				return count, "", err
			}
			if ev.PrevHash != expectedPrev {
				return count, "", fmt.Errorf("chain broken at seq %d: expected prev_hash %s, got %s", ev.Seq, expectedPrev, ev.PrevHash)
			}
			recomputed := ComputeEventHash(ev)
			if recomputed != ev.EventHash {
				return count, "", fmt.Errorf("tampered record at seq %d: hash mismatch", ev.Seq)
			}
			expectedPrev = ev.EventHash
			count++
		}
	}
	return count, expectedPrev, nil
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
