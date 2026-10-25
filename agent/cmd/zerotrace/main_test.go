package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/chuanjin/zerotrace/agent/internal/breaker"
	"github.com/chuanjin/zerotrace/agent/internal/config"
	"github.com/chuanjin/zerotrace/agent/internal/masker"
	"github.com/chuanjin/zerotrace/agent/internal/proxy"
	"github.com/chuanjin/zerotrace/agent/internal/storage"
)

func TestZeroTraceEndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zerotrace-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Mock Upstream Anthropic Server that inspects what actually left the perimeter
	var upstreamReceivedBodies []string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyStr := string(b)
		upstreamReceivedBodies = append(upstreamReceivedBodies, bodyStr)

		// Upstream echoes back the masked tokens so we can verify inbound unmasking restores them
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":    "msg_upstream_01",
			"model": "claude-opus-4-6",
			"content": []map[string]string{
				{"type": "text", "text": "Confirmed user record for: " + bodyStr},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockUpstream.Close()

	cfg := config.DefaultConfig()
	cfg.DataDir = tmpDir
	cfg.UpstreamAnthropic = mockUpstream.URL
	cfg.Guardrails.MaxIdenticalRetries = 2 // Trip on 3rd identical call

	m := masker.New(cfg.HMACSecret)
	b := breaker.New(cfg.Guardrails.MaxSessionCostUSD, cfg.Guardrails.MaxDailyCostUSD, cfg.Guardrails.MaxIdenticalRetries)
	st, err := storage.New(cfg.DataDir, cfg.AccountID, cfg.E2EEKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(proxy.NewServer(cfg, m, b, st).Handler())
	defer srv.Close()

	// 2. Send request with Swedish Personnummer, Email, IBAN, and API Key
	sensitivePrompt := `{"model":"claude-opus-4-6","messages":[{"role":"user","content":"Debug customer erik.lindqvist@volvo.com with Personnummer 19880412-5531, IBAN SE4550000000058398257466 and token sk-ant-api03-secretkey999999"}]}`
	req, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", bytes.NewBufferString(sensitivePrompt))
	req.Header.Set("X-ZeroTrace-Session", "sess-gothenburg-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(respBytes))
	}

	// Verify upstream NEVER saw real PII
	if len(upstreamReceivedBodies) != 1 {
		t.Fatalf("expected 1 upstream call, got %d", len(upstreamReceivedBodies))
	}
	upBody := upstreamReceivedBodies[0]
	for _, secret := range []string{"erik.lindqvist@volvo.com", "19880412-5531", "SE4550000000058398257466", "sk-ant-api03-secretkey999999"} {
		if strings.Contains(upBody, secret) {
			t.Errorf("GDPR LEAK! Upstream received raw sensitive value %q in body: %s", secret, upBody)
		}
	}

	// Verify developer received de-anonymized response seamlessly
	clientView := string(respBytes)
	if !strings.Contains(clientView, "erik.lindqvist@volvo.com") || !strings.Contains(clientView, "19880412-5531") {
		t.Errorf("Inbound unmasking failed! Client saw: %s", clientView)
	}

	// 3. Test Doom-Loop Circuit Breaker (send identical request 2 more times; 3rd total should trip 429)
	req2, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", bytes.NewBufferString(sensitivePrompt))
	req2.Header.Set("X-ZeroTrace-Session", "sess-gothenburg-01")
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("2nd call should pass, got %d", resp2.StatusCode)
	}

	req3, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", bytes.NewBufferString(sensitivePrompt))
	req3.Header.Set("X-ZeroTrace-Session", "sess-gothenburg-01")
	resp3, _ := http.DefaultClient.Do(req3)
	resp3Bytes, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 3rd identical call to trip 429 Doom-Loop breaker, got %d: %s", resp3.StatusCode, string(resp3Bytes))
	}
	if resp3.Header.Get("X-ZeroTrace-Breaker") != "DOOM_LOOP_DETECTED" {
		t.Errorf("expected DOOM_LOOP_DETECTED header, got %s", resp3.Header.Get("X-ZeroTrace-Breaker"))
	}

	// 4. Verify SHA-256 Cryptographic Audit Chain
	count, head, err := storage.VerifyAuditChain(tmpDir)
	if err != nil {
		t.Fatalf("Audit chain verification failed: %v", err)
	}
	if count != 3 || head == "" {
		t.Fatalf("expected 3 chained audit events, got %d (head=%s)", count, head)
	}

	// 5. Verify Apache Parquet v2 generation & HTTP Range serving for DuckDB-Wasm
	pResp, err := http.Get(srv.URL + "/telemetry.parquet")
	if err != nil {
		t.Fatal(err)
	}
	pBytes, _ := io.ReadAll(pResp.Body)
	pResp.Body.Close()
	if len(pBytes) < 4 || string(pBytes[:4]) != "PAR1" || string(pBytes[len(pBytes)-4:]) != "PAR1" {
		t.Fatalf("expected valid Apache Parquet file (PAR1 magic bytes), got len=%d", len(pBytes))
	}

	// 6. Verify BYOC S3/R2 SigV4 upload & CORS provisioning against a mock S3 server
	var s3Objects = make(map[string]int)
	var corsConfigured bool
	mockS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.RawQuery == "cors=" {
			corsConfigured = true
			w.WriteHeader(http.StatusOK)
			return
		}
		b, _ := io.ReadAll(r.Body)
		s3Objects[r.URL.Path] = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockS3.Close()

	s3c := storage.NewS3Client(config.StorageConf{
		Mode:      "s3",
		Endpoint:  mockS3.URL,
		Bucket:    "zerotrace-eu-vault",
		Region:    "eu-north-1",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err := s3c.EnsureBucketAndCORS(); err != nil {
		t.Fatalf("S3 EnsureBucketAndCORS failed: %v", err)
	}
	if !corsConfigured {
		t.Errorf("expected S3 CORS configuration to be applied")
	}
	st.SetS3Client(s3c)

	// Trigger one more call on a fresh session to verify live S3 Parquet upload
	req4, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", bytes.NewBufferString(sensitivePrompt))
	req4.Header.Set("X-ZeroTrace-Session", "sess-s3-sync")
	resp4, _ := http.DefaultClient.Do(req4)
	resp4.Body.Close()

	if s3Objects["/zerotrace-eu-vault/telemetry.parquet"] == 0 || s3Objects["/zerotrace-eu-vault/manifest.json"] == 0 {
		t.Errorf("expected S3 uploads for telemetry.parquet and manifest.json, got %v", s3Objects)
	}

	// 7. Verify Cross-Chunk SSE Stream Unmasking (pseudonym split across 3 tiny chunks)
	sanitized, _ := m.MaskOutbound("Contact erik.lindqvist@volvo.com or 19880412-5531")
	// Extract the fake email generated by masker
	var fakeEmail string
	for _, word := range strings.Fields(sanitized) {
		if strings.HasSuffix(word, "@masked.zerotrace.eu") {
			fakeEmail = word
		}
	}
	if fakeEmail == "" {
		t.Fatalf("expected fake email in sanitized string: %s", sanitized)
	}
	su := m.NewStreamUnmasker()
	// Split fakeEmail into 3 chunks right in the middle
	part1 := "data: {\"text\":\" Send to " + fakeEmail[:5]
	part2 := fakeEmail[5:15]
	part3 := fakeEmail[15:] + " immediately\"}\n\n"
	reconstructed := su.ProcessChunk(part1) + su.ProcessChunk(part2) + su.ProcessChunk(part3) + su.Flush()
	if !strings.Contains(reconstructed, "erik.lindqvist@volvo.com") || strings.Contains(reconstructed, "@masked.zerotrace.eu") {
		t.Errorf("Cross-chunk SSE unmasking failed! Reconstructed: %s", reconstructed)
	}

	// 8. Verify Cache Churn Alert detection (repeated 50K cache writes with 0 cache reads)
	_ = b.EvaluatePreCall("sess-churn", "turn-1", 0.01)
	_ = b.EvaluatePreCall("sess-churn", "turn-2", 0.01)
	churnAlert, wastedUSD := b.EvaluateCacheChurn("sess-churn", 0, 50000, 2000, 15.0)
	if !churnAlert || wastedUSD <= 0 {
		t.Errorf("expected Cache Churn Alert on 50K cache rebuild with 0 cache read, got alert=%v wasted=%f", churnAlert, wastedUSD)
	}
}
