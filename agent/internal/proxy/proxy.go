package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chuanjin/zerotrace/agent/internal/breaker"
	"github.com/chuanjin/zerotrace/agent/internal/config"
	"github.com/chuanjin/zerotrace/agent/internal/masker"
	"github.com/chuanjin/zerotrace/agent/internal/storage"
)

type Server struct {
	cfg     *config.Config
	masker  *masker.Masker
	breaker *breaker.Breaker
	store   *storage.Store
	client  *http.Client
}

func NewServer(cfg *config.Config, m *masker.Masker, b *breaker.Breaker, s *storage.Store) *Server {
	return &Server{
		cfg:     cfg,
		masker:  m,
		breaker: b,
		store:   s,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Pricing table per 1M tokens (Input / Output)
func estimateCost(model string, tokensIn, tokensOut int) float64 {
	m := strings.ToLower(model)
	inRate, outRate := 3.0, 15.0 // Default Sonnet-class
	switch {
	case strings.Contains(m, "opus"):
		inRate, outRate = 15.0, 75.0
	case strings.Contains(m, "haiku") || strings.Contains(m, "mini") || strings.Contains(m, "flash"):
		inRate, outRate = 0.30, 1.20
	case strings.Contains(m, "gpt-4") || strings.Contains(m, "o3"):
		inRate, outRate = 5.0, 15.0
	}
	return (float64(tokensIn)/1_000_000.0)*inRate + (float64(tokensOut)/1_000_000.0)*outRate
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/manifest", s.handleManifest)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/anthropic/", s.handleProxy("anthropic"))
	mux.HandleFunc("/openai/", s.handleProxy("openai"))
	// Also handle root /v1/messages and /v1/chat/completions directly for zero-config base URLs
	mux.HandleFunc("/v1/messages", s.handleProxy("anthropic"))
	mux.HandleFunc("/v1/chat/completions", s.handleProxy("openai"))
	return enableCORS(mux)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, anthropic-version, X-ZeroTrace-Session, X-ZeroTrace-Repo")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"service":    "zerotrace-agent",
		"account_id": s.cfg.AccountID,
		"gdpr_mask":  s.cfg.GDPRMaskingEnabled,
	})
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.GetManifest())
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	count, head, err := storage.VerifyAuditChain(s.cfg.DataDir)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"verified": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"verified":       true,
		"records_checked": count,
		"chain_head_sha256": head,
		"standard":       "EU AI Act Art. 12 / GDPR Art. 32 Tamper-Evident Log",
	})
}

func (s *Server) handleProxy(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()

		rawBody := string(bodyBytes)
		var parsed map[string]any
		_ = json.Unmarshal(bodyBytes, &parsed)

		model, _ := parsed["model"].(string)
		if model == "" {
			model = "claude-sonnet-4-5"
		}
		sessionID := r.Header.Get("X-ZeroTrace-Session")
		if sessionID == "" {
			sessionID = "default-cli-session"
		}
		repo := r.Header.Get("X-ZeroTrace-Repo")
		if repo == "" {
			repo = "local-workspace"
		}

		// 1. GDPR Deterministic PII & Secret Scrubbing BEFORE leaving the machine
		sanitizedBody := rawBody
		var mStats masker.MaskStats
		if s.cfg.GDPRMaskingEnabled {
			sanitizedBody, mStats = s.masker.MaskOutbound(rawBody)
		}

		estTokensIn := len(sanitizedBody) / 4
		if estTokensIn < 10 {
			estTokensIn = 10
		}
		estCost := estimateCost(model, estTokensIn, 250)

		// 2. Active Circuit Breaker (Doom-Loop & Budget Enforcement)
		chk := s.breaker.EvaluatePreCall(sessionID, sanitizedBody, estCost)
		if !chk.Allowed {
			_, _ = s.store.Append(storage.AuditEvent{
				SessionID:     sessionID,
				Provider:      provider,
				Model:         model,
				Repo:          repo,
				TokensIn:      estTokensIn,
				TokensOut:     0,
				CostUSD:       0,
				SavedUSD:      estCost,
				LatencyMs:     time.Since(start).Milliseconds(),
				Status:        chk.Code,
				PIIRedactions: mStats.TotalRedactions,
				PIICategories: mStats.ByCategory,
			}, sanitizedBody)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "3600")
			w.Header().Set("X-ZeroTrace-Breaker", chk.Code)
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    "zerotrace_circuit_breaker",
					"code":    chk.Code,
					"message": "🛑 [ZeroTrace Circuit Breaker] " + chk.Reason,
				},
			})
			return
		}

		// 3. Forward to Upstream (or Mock Upstream if X-ZeroTrace-Mock header or mock upstream URL is set)
		var respBody string
		statusCode := http.StatusOK
		tokensOut := 64

		if r.Header.Get("X-ZeroTrace-Mock") == "1" || strings.HasPrefix(s.cfg.UpstreamAnthropic, "mock://") {
			// Built-in deterministic echo/simulator for offline verification & testing
			respBody = fmt.Sprintf(`{"id":"msg_zt_sim","model":%q,"role":"assistant","content":[{"type":"text","text":"Processed sanitized request cleanly. Echoing reference: %s"}],"usage":{"input_tokens":%d,"output_tokens":48}}`,
				model, extractPreview(sanitizedBody), estTokensIn)
			tokensOut = 48
		} else {
			upstreamBase := s.cfg.UpstreamAnthropic
			targetPath := strings.TrimPrefix(r.URL.Path, "/anthropic")
			if provider == "openai" {
				upstreamBase = s.cfg.UpstreamOpenAI
				targetPath = strings.TrimPrefix(r.URL.Path, "/openai")
			}
			targetURL := strings.TrimRight(upstreamBase, "/") + targetPath
			upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader([]byte(sanitizedBody)))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for k, vv := range r.Header {
				if !strings.EqualFold(k, "Host") && !strings.EqualFold(k, "Content-Length") {
					for _, v := range vv {
						upReq.Header.Add(k, v)
					}
				}
			}
			upResp, err := s.client.Do(upReq)
			if err != nil {
				http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer upResp.Body.Close()
			statusCode = upResp.StatusCode
			b, _ := io.ReadAll(upResp.Body)
			respBody = string(b)
			tokensOut = len(respBody) / 4
		}

		actualCost := estimateCost(model, estTokensIn, tokensOut)

		// 4. Append Zero-Knowledge Encrypted + SHA-256 Chained Audit Event
		ev, _ := s.store.Append(storage.AuditEvent{
			SessionID:     sessionID,
			Provider:      provider,
			Model:         model,
			Repo:          repo,
			TokensIn:      estTokensIn,
			TokensOut:     tokensOut,
			CostUSD:       actualCost,
			SavedUSD:      0,
			LatencyMs:     time.Since(start).Milliseconds(),
			Status:        "OK",
			PIIRedactions: mStats.TotalRedactions,
			PIICategories: mStats.ByCategory,
		}, sanitizedBody)

		// 5. Unmask Pseudonyms in Response Before Returning to Developer
		finalResp := respBody
		if s.cfg.GDPRMaskingEnabled {
			finalResp = s.masker.UnmaskInbound(respBody)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ZeroTrace-Event-Hash", ev.EventHash)
		w.Header().Set("X-ZeroTrace-Redactions", fmt.Sprintf("%d", mStats.TotalRedactions))
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(finalResp))
	}
}

func extractPreview(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 180 {
		return s[:180] + "..."
	}
	return s
}
