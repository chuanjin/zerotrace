package storage

import (
	"bytes"
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

// AuditEvent represents a single immutable telemetry record compliant with EU AI Act Art. 12 & GDPR.
type AuditEvent struct {
	Seq              int64          `json:"seq" parquet:"seq"`
	Timestamp        string         `json:"timestamp" parquet:"timestamp"`
	SessionID        string         `json:"session_id" parquet:"session_id"`
	Provider         string         `json:"provider" parquet:"provider"`
	Model            string         `json:"model" parquet:"model"`
	Repo             string         `json:"repo,omitempty" parquet:"repo"`
	TokensIn          int            `json:"tokens_in" parquet:"tokens_in"`
	TokensCacheRead   int            `json:"tokens_cache_read" parquet:"tokens_cache_read"`
	TokensCacheWrite  int            `json:"tokens_cache_write" parquet:"tokens_cache_write"`
	TokensOut         int            `json:"tokens_out" parquet:"tokens_out"`
	CostUSD           float64        `json:"cost_usd" parquet:"cost_usd"`
	SavedUSD          float64        `json:"saved_usd" parquet:"saved_usd"`           // Money saved when circuit breaker trips
	CacheWastedUSD    float64        `json:"cache_wasted_usd" parquet:"cache_wasted_usd"` // Extra cost caused by cache churn/rebuild
	CacheChurnAlert   bool           `json:"cache_churn_alert" parquet:"cache_churn_alert"`
	LatencyMs         int64          `json:"latency_ms" parquet:"latency_ms"`
	Status           string         `json:"status" parquet:"status"` // "OK", "DOOM_LOOP_DETECTED", "SESSION_BUDGET_EXCEEDED"
	PIIRedactions    int            `json:"pii_redactions" parquet:"pii_redactions"`
	PIICategories    map[string]int `json:"pii_categories,omitempty" parquet:"-"`
	EncryptedPayload string         `json:"encrypted_payload" parquet:"encrypted_payload"` // AES-256-GCM ciphertext (Zero-Knowledge)
	PrevHash         string         `json:"prev_hash" parquet:"prev_hash"`                 // Cryptographic tamper-evident chain
	EventHash        string         `json:"event_hash" parquet:"event_hash"`
}

type Manifest struct {
	AccountID            string         `json:"account_id"`
	UpdatedAt            string         `json:"updated_at"`
	TotalRequests        int64          `json:"total_requests"`
	TotalCostUSD         float64        `json:"total_cost_usd"`
	TotalSavedUSD        float64        `json:"total_saved_usd"`
	TotalCacheWastedUSD  float64        `json:"total_cache_wasted_usd"`
	TotalCacheChurns     int64          `json:"total_cache_churns"`
	TotalPIIRedactions   int64          `json:"total_pii_redactions"`
	TotalLoopsBlocked    int64          `json:"total_loops_blocked"`
	PIICategoryBreakdown map[string]int `json:"pii_category_breakdown"`
	ChainHeadHash        string         `json:"chain_head_hash"`
	ChainVerified        bool           `json:"chain_verified"`
	LatestParquetFile    string         `json:"latest_parquet_file"`
	S3Synced             bool           `json:"s3_synced"`
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
	allEvents []AuditEvent
	s3Client  *S3Client
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

func (s *Store) SetS3Client(c *S3Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s3Client = c
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
	// Load existing JSONL events so Parquet snapshots contain the full day's dataset
	files, _ := filepath.Glob(filepath.Join(s.dataDir, "audit-*.jsonl"))
	for _, file := range files {
		if raw, err := os.ReadFile(file); err == nil {
			for _, line := range splitNonEmptyLines(string(raw)) {
				var ev AuditEvent
				if err := json.Unmarshal([]byte(line), &ev); err == nil {
					s.allEvents = append(s.allEvents, ev)
				}
			}
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

func formatCategories(cats map[string]int) string {
	if len(cats) == 0 {
		return ""
	}
	keys := make([]string, 0, len(cats))
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, cats[k])
	}
	return strings.Join(parts, ",")
}

// ComputeEventHash computes a canonical deterministic SHA-256 digest covering all business,
// metadata, cost, token, payload, and chaining fields of an AuditEvent.
func ComputeEventHash(ev AuditEvent) string {
	churn := "0"
	if ev.CacheChurnAlert {
		churn = "1"
	}
	canonical := fmt.Sprintf(
		"seq=%d\nts=%s\nsess=%s\nprov=%s\nmodel=%s\nrepo=%s\n"+
			"tin=%d\ntcr=%d\ntcw=%d\ntout=%d\n"+
			"cost=%.6f\nsaved=%.6f\nwasted=%.6f\nchurn=%s\nlat=%d\n"+
			"status=%s\npii_cnt=%d\npii_cats=%s\npayload=%s\nprev=%s",
		ev.Seq, ev.Timestamp, ev.SessionID, ev.Provider, ev.Model, ev.Repo,
		ev.TokensIn, ev.TokensCacheRead, ev.TokensCacheWrite, ev.TokensOut,
		ev.CostUSD, ev.SavedUSD, ev.CacheWastedUSD, churn, ev.LatencyMs,
		ev.Status, ev.PIIRedactions, formatCategories(ev.PIICategories), ev.EncryptedPayload, ev.PrevHash,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// buildParquetBytes serializes AuditEvents into an Apache Parquet v2 columnar byte slice.
func buildParquetBytes(events []AuditEvent) ([]byte, error) {
	var buf bytes.Buffer
	writer := parquet.NewGenericWriter[AuditEvent](&buf, parquet.Compression(&parquet.Snappy))
	if _, err := writer.Write(events); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	s.allEvents = append(s.allEvents, ev)

	// 1. Append to daily JSONL log
	day := time.Now().UTC().Format("2006-01-02")
	logPath := filepath.Join(s.dataDir, fmt.Sprintf("audit-%s.jsonl", day))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return ev, err
	}
	line, _ := json.Marshal(ev)
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()

	// 2. Write columnar Apache Parquet file (`telemetry.parquet` & daily partition)
	parquetRel := fmt.Sprintf("dt=%s/audit-%s.parquet", day, day)
	parquetBytes, pErr := buildParquetBytes(s.allEvents)
	if pErr == nil {
		_ = os.MkdirAll(filepath.Join(s.dataDir, "dt="+day), 0700)
		_ = os.WriteFile(filepath.Join(s.dataDir, parquetRel), parquetBytes, 0600)
		_ = os.WriteFile(filepath.Join(s.dataDir, "telemetry.parquet"), parquetBytes, 0600)
		s.manifest.LatestParquetFile = "telemetry.parquet"
	}

	// 3. Update manifest
	s.manifest.UpdatedAt = ev.Timestamp
	s.manifest.TotalRequests = s.seq
	s.manifest.TotalCostUSD += ev.CostUSD
	s.manifest.TotalSavedUSD += ev.SavedUSD
	s.manifest.TotalCacheWastedUSD += ev.CacheWastedUSD
	if ev.CacheChurnAlert {
		s.manifest.TotalCacheChurns++
	}
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

	// 4. Optional BYOC S3 / Cloudflare R2 direct upload (Zero-Knowledge)
	if s.s3Client != nil && s.s3Client.Enabled() && len(parquetBytes) > 0 {
		err1 := s.s3Client.PutObject("telemetry.parquet", "application/vnd.apache.parquet", parquetBytes)
		err2 := s.s3Client.PutObject(parquetRel, "application/vnd.apache.parquet", parquetBytes)
		s.manifest.S3Synced = (err1 == nil && err2 == nil)
	}

	mBytes, _ := json.MarshalIndent(s.manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(s.dataDir, "manifest.json"), mBytes, 0600)
	if s.s3Client != nil && s.s3Client.Enabled() {
		_ = s.s3Client.PutObject("manifest.json", "application/json", mBytes)
	}

	return ev, nil
}

func (s *Store) GetManifest() Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifest
}

func (s *Store) GetParquetBytes() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pPath := filepath.Join(s.dataDir, "telemetry.parquet")
	if b, err := os.ReadFile(pPath); err == nil {
		return b, nil
	}
	return buildParquetBytes(s.allEvents)
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
