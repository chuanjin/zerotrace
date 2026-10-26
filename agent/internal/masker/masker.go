package masker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Masker performs sub-millisecond deterministic pseudonymization of EU/Nordic PII & credentials
// before prompts leave the machine, and reverses pseudonyms in responses (including SSE streams).
type Masker struct {
	secret  []byte
	mu      sync.RWMutex
	forward map[string]string // real -> fake (guarantees determinism)
	reverse map[string]string // fake -> real (guarantees conflict-free 1-to-1 reverse mapping)
}

type MaskStats struct {
	TotalRedactions int            `json:"total_redactions"`
	ByCategory      map[string]int `json:"by_category"`
}

var (
	// Email addresses
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// Swedish Personnummer (YYYYMMDD-XXXX, YYMMDD-XXXX, or with + for pensioners)
	rePersonnummer = regexp.MustCompile(`\b(?:19|20)?\d{6}[-+]\d{4}\b`)
	// European IBAN (supports both compact e.g. SE4550000000058398257466 and space-separated e.g. SE45 5000 0000 0583 9825 7466)
	reIBAN = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b`)
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
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}
}

func (m *Masker) getHMACDigest(category, realVal string, salt int) string {
	mac := hmac.New(sha256.New, m.secret)
	if salt == 0 {
		mac.Write([]byte(category + ":" + realVal))
	} else {
		mac.Write([]byte(fmt.Sprintf("%s:%d:%s", category, salt, realVal)))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (m *Masker) getOrRegisterFake(category, realVal string, generateFake func(digest string) string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if fake, ok := m.forward[realVal]; ok {
		return fake
	}

	for salt := 0; ; salt++ {
		digest := m.getHMACDigest(category, realVal, salt)
		fake := generateFake(digest)
		existingReal, exists := m.reverse[fake]
		if !exists || existingReal == realVal {
			m.forward[realVal] = fake
			m.reverse[fake] = realVal
			return fake
		}
		// Hash collision detected: next salt iteration produces alternate unique pseudonym
	}
}

// MaskOutbound scrubs PII/secrets deterministically and returns the sanitized string + audit count.
func (m *Masker) MaskOutbound(input string) (string, MaskStats) {
	stats := MaskStats{ByCategory: make(map[string]int)}
	out := input

	// 1. API Keys & Secrets (64-bit entropy tag)
	out = reAPIKey.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, "zt_masked_") {
			return match
		}
		fake := m.getOrRegisterFake("key", match, func(d string) string {
			return fmt.Sprintf("zt_masked_key_%s", d[:16])
		})
		stats.TotalRedactions++
		stats.ByCategory["SECRET_KEY"]++
		return fake
	})

	// 2. Swedish Personnummer (10-digit and 12-digit format, 8-digit entropy + collision avoidance)
	out = rePersonnummer.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasPrefix(match, "1900") {
			return match
		}
		fake := m.getOrRegisterFake("pnr", match, func(d string) string {
			digits := make([]byte, 8)
			for i := 0; i < 8; i++ {
				digits[i] = '0' + (d[i] % 10)
			}
			return fmt.Sprintf("1900%s-%s", string(digits[:4]), string(digits[4:]))
		})
		stats.TotalRedactions++
		stats.ByCategory["SE_PERSONNUMMER"]++
		return fake
	})

	// 3. EU IBANs (compact or space-separated, 56-bit entropy tag)
	out = reIBAN.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasPrefix(match, "SE00ZT") {
			return match
		}
		fake := m.getOrRegisterFake("iban", match, func(d string) string {
			return fmt.Sprintf("SE00ZT%s0000", strings.ToUpper(d[:14]))
		})
		stats.TotalRedactions++
		stats.ByCategory["EU_IBAN"]++
		return fake
	})

	// 4. Emails (64-bit entropy tag)
	out = reEmail.ReplaceAllStringFunc(out, func(match string) string {
		if strings.HasSuffix(match, "@masked.zerotrace.eu") {
			return match
		}
		fake := m.getOrRegisterFake("email", match, func(d string) string {
			return fmt.Sprintf("u_%s@masked.zerotrace.eu", d[:16])
		})
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
	keys := make([]string, 0, len(m.reverse))
	for fake := range m.reverse {
		keys = append(keys, fake)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	out := input
	for _, fake := range keys {
		realVal := m.reverse[fake]
		if strings.Contains(out, fake) {
			out = strings.ReplaceAll(out, fake, realVal)
		}
	}
	return out
}

// StreamUnmasker handles cross-chunk boundary PII unmasking for Server-Sent Events (SSE) / chunked streams.
type StreamUnmasker struct {
	masker  *Masker
	pending string
}

func (m *Masker) NewStreamUnmasker() *StreamUnmasker {
	return &StreamUnmasker{masker: m}
}

func (su *StreamUnmasker) ProcessChunk(chunk string) string {
	combined := su.pending + chunk
	su.pending = ""

	// First unmask any complete pseudonyms now present in combined
	combined = su.masker.UnmaskInbound(combined)

	// Check if any suffix of `combined` (up to max pseudonym length 64) is a prefix of any registered pseudonym
	holdbackLen := su.findLongestPrefixSuffix(combined)
	if holdbackLen > 0 {
		safePart := combined[:len(combined)-holdbackLen]
		su.pending = combined[len(combined)-holdbackLen:]
		return safePart
	}
	return combined
}

func (su *StreamUnmasker) Flush() string {
	if su.pending == "" {
		return ""
	}
	out := su.masker.UnmaskInbound(su.pending)
	su.pending = ""
	return out
}

func (su *StreamUnmasker) findLongestPrefixSuffix(s string) int {
	su.masker.mu.RLock()
	defer su.masker.mu.RUnlock()
	if len(su.masker.reverse) == 0 || len(s) == 0 {
		return 0
	}
	maxCheck := 64
	if len(s) < maxCheck {
		maxCheck = len(s)
	}
	for l := maxCheck; l >= 1; l-- {
		suffix := s[len(s)-l:]
		for fake := range su.masker.reverse {
			if len(fake) > l && strings.HasPrefix(fake, suffix) {
				return l
			}
		}
	}
	return 0
}
