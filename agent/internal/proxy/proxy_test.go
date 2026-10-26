package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/chuanjin/zerotrace/agent/internal/breaker"
	"github.com/chuanjin/zerotrace/agent/internal/config"
	"github.com/chuanjin/zerotrace/agent/internal/masker"
	"github.com/chuanjin/zerotrace/agent/internal/storage"
)

func TestSecurityMiddlewareCORSAndAuth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zerotrace-proxy-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := config.DefaultConfig()
	cfg.DataDir = tmpDir
	cfg.APIToken = "secret-token-123"
	cfg.AllowedOrigins = []string{"https://app.zerotrace.eu"}

	m := masker.New(cfg.HMACSecret)
	b := breaker.New(cfg.Guardrails.MaxSessionCostUSD, cfg.Guardrails.MaxDailyCostUSD, cfg.Guardrails.MaxIdenticalRetries)
	st, err := storage.New(cfg.DataDir, cfg.AccountID, cfg.E2EEKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewServer(cfg, m, b, st).Handler())
	defer srv.Close()

	// 1. Untrusted origin preflight should be 403 Forbidden
	req, _ := http.NewRequest("OPTIONS", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "https://malicious.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for untrusted origin preflight, got %d", resp.StatusCode)
	}

	// 2. Untrusted origin GET should be 403 Forbidden
	req, _ = http.NewRequest("GET", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "https://malicious.example.com")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for untrusted origin GET, got %d", resp.StatusCode)
	}

	// 3. Allowed localhost origin preflight should be 204 No Content with CORS headers
	req, _ = http.NewRequest("OPTIONS", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 No Content for localhost preflight, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Errorf("expected Access-Control-Allow-Origin: http://localhost:5173, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}

	// 4. Allowed configured origin GET with missing auth token should be 401 Unauthorized
	req, _ = http.NewRequest("GET", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "https://app.zerotrace.eu")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", resp.StatusCode)
	}

	// 5. Allowed origin GET with valid Bearer token should be 200 OK
	req, _ = http.NewRequest("GET", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "https://app.zerotrace.eu")
	req.Header.Set("Authorization", "Bearer secret-token-123")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for authorized request, got %d", resp.StatusCode)
	}

	// 6. Health check is accessible without token
	req, _ = http.NewRequest("GET", srv.URL+"/health", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /health, got %d", resp.StatusCode)
	}

	// 7. Null origin (local file:// page) preflight should be allowed
	req, _ = http.NewRequest("OPTIONS", srv.URL+"/api/manifest", nil)
	req.Header.Set("Origin", "null")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 No Content for null origin preflight, got %d", resp.StatusCode)
	}
}
