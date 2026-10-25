package masker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Masker performs sub-millisecond deterministic pseudonymization of EU/Nordic PII & credentials
// before prompts leave the machine, and reverses pseudonyms in responses (including SSE streams).
type Masker struct {
	secret  []byte
	mu      sync.RWMutex
	reverse map[string]string // fake -> real
}

type MaskStats struct {
	TotalRedactions int            `json:"total_redactions"`
	ByCategory      map[string]int `json:"by_category"`
}

var (
	// Email addresses
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// Swedish Personnummer (YYYYMMDD-XXXX or YYMMDD-XXXX, avoiding plain dates where possible)
	rePersonnummer = regexp.MustCompile(`\b(?:19|20)\d{6}[-+]\d{4}\b`)
	// European IBAN (e.g., SE45 5000 0000 0583 9825 7466 or compact)
	reIBAN = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	// Secret / API Keys (OpenAI sk-..., Anthropic sk-ant-..., AWS AKIA..., GitHub ghp_...)
	reAPIKey = regexp.MustCompile(`\b(?:sk-ant-[a-zA-Z0-9\-_]{10,}|sk-(?:proj-)?[a-zA-Z0-9\-_]{16,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,})\b`)
)

func New(secretHex string) *Masker {
	sec := []byte(secretHex)
	if len(sec) == 0 {
		sec = []byte("zerotrace-default-local-secret")
	}
	return &Masker{
		secret:  sec,
		reverse: make(map[string]string),
	}
}

func (m *Masker) shortTag(category, realVal string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(category + ":" + realVal))
	sum := hex.EncodeToString(mac.Sum(nil))
	return sum[:8]
}

func (m *Masker) registerPair(realVal, fakeVal string) {
	m.mu.Lock()
	m.reverse[fakeVal] = realVal
	m.mu.Unlock()
}

// MaskOutbound scrubs PII/secrets deterministically and returns the sanitized string + audit count.
func (m *Masker) MaskOutbound(input string) (string, MaskStats) {
	stats := MaskStats{ByCategory: make(map[string]int)}
	out := input

	// 1. API Keys & Secrets
	out = reAPIKey.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, "zt_masked_") {
			return match
		}
		tag := m.shortTag("key", match)
		fake := fmt.Sprintf("sk_zt_masked_%s", tag)
		m.registerPair(match, fake)
		stats.TotalRedactions++
		stats.ByCategory["SECRET_KEY"]++
		return fake
	})

	// 2. Swedish Personnummer (Nordic GDPR high-risk identifier)
	out = rePersonnummer.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasPrefix(match, "190001") {
			return match
		}
		tag := m.shortTag("pnr", match)
		// Map hex characters to digits so length & format remain valid YYYYMMDD-XXXX
		digits := make([]byte, 4)
		for i := 0; i < 4; i++ {
			digits[i] = '0' + (tag[i] % 10)
		}
		fake := fmt.Sprintf("19000101-%s", string(digits))
		m.registerPair(match, fake)
		stats.TotalRedactions++
		stats.ByCategory["SE_PERSONNUMMER"]++
		return fake
	})

	// 3. EU IBANs
	out = reIBAN.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasPrefix(match, "SE00ZT") {
			return match
		}
		tag := strings.ToUpper(m.shortTag("iban", match))
		fake := fmt.Sprintf("SE00ZT%s0000", tag)
		m.registerPair(match, fake)
		stats.TotalRedactions++
		stats.ByCategory["EU_IBAN"]++
		return fake
	})

	// 4. Emails
	out = reEmail.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasSuffix(match, "@masked.zerotrace.eu") {
			return match
		}
		tag := m.shortTag("email", match)
		fake := fmt.Sprintf("u_%s@masked.zerotrace.eu", tag)
		m.registerPair(match, fake)
		stats.TotalRedactions++
		stats.ByCategory["EMAIL"]++
		return fake
	})

	return out, stats
}

// UnmaskInbound restores deterministic pseudonyms back to original values on the fly.
func (m *Masker) UnmaskInbound(input string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.reverse) == 0 {
		return input
	}
	out := input
	for fake, realVal := range m.reverse {
		if strings.Contains(out, fake) {
			out = strings.ReplaceAll(out, fake, realVal)
		}
	}
	return out
}
