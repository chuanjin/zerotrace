package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
func modelRates(model string) (inRate, outRate float64) {
	m := strings.ToLower(model)
	inRate, outRate = 3.0, 15.0 // Default Sonnet-class
	switch {
	case strings.Contains(m, "opus"):
		inRate, outRate = 15.0, 75.0
	case strings.Contains(m, "deepseek-reasoner") || strings.Contains(m, "deepseek-r1"):
		inRate, outRate = 0.55, 2.19
	case strings.Contains(m, "deepseek-chat") || strings.Contains(m, "deepseek-v3"):
		inRate, outRate = 0.14, 0.28
	case strings.Contains(m, "gemini-2.0") || strings.Contains(m, "gemini-1.5-pro"):
		inRate, outRate = 1.25, 5.00
	case strings.Contains(m, "haiku") || strings.Contains(m, "mini") || strings.Contains(m, "flash"):
		inRate, outRate = 0.30, 1.20
	case strings.Contains(m, "gpt-4") || strings.Contains(m, "o3"):
		inRate, outRate = 5.0, 15.0
	}
	return inRate, outRate
}

func estimateCostWithCache(model string, uncachedIn, cacheRead, cacheWrite, tokensOut int) float64 {
	inRate, outRate := modelRates(model)
	// Anthropic/OpenAI standard: Cache Read = 0.1x input rate, Cache Write = 1.25x input rate
	costIn := (float64(uncachedIn) / 1_000_000.0) * inRate
	costCacheRead := (float64(cacheRead) / 1_000_000.0) * (inRate * 0.10)
	costCacheWrite := (float64(cacheWrite) / 1_000_000.0) * (inRate * 1.25)
	costOut := (float64(tokensOut) / 1_000_000.0) * outRate
	return costIn + costCacheRead + costCacheWrite + costOut
}

func estimateCost(model string, tokensIn, tokensOut int) float64 {
	return estimateCostWithCache(model, tokensIn, 0, 0, tokensOut)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/manifest", s.handleManifest)
	mux.HandleFunc("/api/telemetry.parquet", s.handleParquet)
	mux.HandleFunc("/telemetry.parquet", s.handleParquet)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/anthropic/", s.handleProxy("anthropic"))
	mux.HandleFunc("/openai/", s.handleProxy("openai"))
	mux.HandleFunc("/deepseek/", s.handleProxy("deepseek"))
	mux.HandleFunc("/gemini/", s.handleProxy("gemini"))
	// Also handle root /v1/messages and /v1/chat/completions directly for zero-config base URLs
	mux.HandleFunc("/v1/messages", s.handleProxy("anthropic"))
	mux.HandleFunc("/v1/chat/completions", s.handleProxy("openai"))
	return s.securityMiddleware(mux)
}

func (s *Server) isOriginAllowed(origin string) bool {
	if origin == "" || origin == "null" {
		return true
	}
	u, err := url.Parse(origin)
	if err == nil {
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" {
			return true
		}
	}
	for _, ao := range s.cfg.AllowedOrigins {
		if ao == "*" || strings.EqualFold(ao, origin) {
			return true
		}
	}
	return false
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.isOriginAllowed(origin) {
				http.Error(w, `{"error":"cross-origin request forbidden from untrusted origin"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Range, Authorization, x-api-key, anthropic-version, X-ZeroTrace-Session, X-ZeroTrace-Repo, X-ZeroTrace-Token")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, X-ZeroTrace-Event-Hash, X-ZeroTrace-Redactions, X-ZeroTrace-Breaker")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		if s.cfg.APIToken != "" && r.URL.Path != "/health" {
			token := r.Header.Get("X-ZeroTrace-Token")
			if token == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					token = strings.TrimSpace(auth[7:])
				}
			}
			if token != s.cfg.APIToken {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized: invalid or missing zero-trace API token"})
				return
			}
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

// handleParquet serves telemetry.parquet with full HTTP Range support so DuckDB-Wasm httpfs can query it directly.
func (s *Server) handleParquet(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.GetParquetBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apache.parquet")
	w.Header().Set("Accept-Ranges", "bytes")
	http.ServeContent(w, r, "telemetry.parquet", time.Now(), bytes.NewReader(data))
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

		// 3. Forward to Upstream (supports both standard JSON and Server-Sent Events SSE streaming)
		var respBody string
		statusCode := http.StatusOK
		tokensOut := 64
		cacheReadTokens := 0
		cacheWriteTokens := 0
		uncachedInTokens := estTokensIn
		isStream, _ := parsed["stream"].(bool)

		if r.Header.Get("X-ZeroTrace-Mock") == "1" || strings.HasPrefix(s.cfg.UpstreamAnthropic, "mock://") {
			respBody = fmt.Sprintf(`{"id":"msg_zt_sim","model":%q,"role":"assistant","content":[{"type":"text","text":"Processed sanitized request cleanly. Echoing reference: %s"}],"usage":{"input_tokens":%d,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":48}}`,
				model, extractPreview(sanitizedBody), estTokensIn)
			tokensOut = 48
		} else {
			upstreamBase := s.cfg.UpstreamAnthropic
			targetPath := strings.TrimPrefix(r.URL.Path, "/anthropic")
			if provider == "openai" {
				upstreamBase = s.cfg.UpstreamOpenAI
				targetPath = strings.TrimPrefix(r.URL.Path, "/openai")
			} else if provider == "deepseek" {
				upstreamBase = s.cfg.UpstreamDeepSeek
				targetPath = strings.TrimPrefix(r.URL.Path, "/deepseek")
			} else if provider == "gemini" {
				upstreamBase = s.cfg.UpstreamGemini
				targetPath = strings.TrimPrefix(r.URL.Path, "/gemini")
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

			isSSE := isStream || strings.Contains(strings.ToLower(upResp.Header.Get("Content-Type")), "text/event-stream")
			if isSSE {
				// Stream response chunks through cross-boundary StreamUnmasker
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("X-ZeroTrace-Redactions", fmt.Sprintf("%d", mStats.TotalRedactions))
				w.WriteHeader(statusCode)
				flusher, _ := w.(http.Flusher)

				su := s.masker.NewStreamUnmasker()
				var fullStreamBuf strings.Builder
				buf := make([]byte, 128)
				for {
					n, readErr := upResp.Body.Read(buf)
					if n > 0 {
						chunkStr := string(buf[:n])
						fullStreamBuf.WriteString(chunkStr)
						outChunk := chunkStr
						if s.cfg.GDPRMaskingEnabled {
							outChunk = su.ProcessChunk(chunkStr)
						}
						if len(outChunk) > 0 {
							_, _ = w.Write([]byte(outChunk))
							if flusher != nil {
								flusher.Flush()
							}
						}
					}
					if readErr != nil {
						break
					}
				}
				if s.cfg.GDPRMaskingEnabled {
					if tail := su.Flush(); len(tail) > 0 {
						_, _ = w.Write([]byte(tail))
						if flusher != nil {
							flusher.Flush()
						}
					}
				}
				respBody = fullStreamBuf.String()
				tokensOut = len(respBody) / 4
				inTok, crTok, cwTok, outTok := parseUsageMetrics(respBody, estTokensIn, tokensOut)
				uncachedInTokens, cacheReadTokens, cacheWriteTokens, tokensOut = inTok, crTok, cwTok, outTok
				inRate, _ := modelRates(model)
				churnAlert, wastedUSD := s.breaker.EvaluateCacheChurn(sessionID, cacheReadTokens, cacheWriteTokens, uncachedInTokens, inRate)
				actualCost := estimateCostWithCache(model, uncachedInTokens, cacheReadTokens, cacheWriteTokens, tokensOut)

				_, _ = s.store.Append(storage.AuditEvent{
					SessionID:        sessionID,
					Provider:         provider,
					Model:            model,
					Repo:             repo,
					TokensIn:         uncachedInTokens,
					TokensCacheRead:  cacheReadTokens,
					TokensCacheWrite: cacheWriteTokens,
					TokensOut:        tokensOut,
					CostUSD:          actualCost,
					SavedUSD:         0,
					CacheWastedUSD:   wastedUSD,
					CacheChurnAlert:  churnAlert,
					LatencyMs:        time.Since(start).Milliseconds(),
					Status:           "OK",
					PIIRedactions:    mStats.TotalRedactions,
					PIICategories:    mStats.ByCategory,
				}, sanitizedBody)
				return
			}

			b, _ := io.ReadAll(upResp.Body)
			respBody = string(b)
			tokensOut = len(respBody) / 4
		}

		inTok, crTok, cwTok, outTok := parseUsageMetrics(respBody, estTokensIn, tokensOut)
		uncachedInTokens, cacheReadTokens, cacheWriteTokens, tokensOut = inTok, crTok, cwTok, outTok
		inRate, _ := modelRates(model)
		churnAlert, wastedUSD := s.breaker.EvaluateCacheChurn(sessionID, cacheReadTokens, cacheWriteTokens, uncachedInTokens, inRate)
		actualCost := estimateCostWithCache(model, uncachedInTokens, cacheReadTokens, cacheWriteTokens, tokensOut)

		// 4. Append Zero-Knowledge Encrypted + SHA-256 Chained Audit Event
		ev, _ := s.store.Append(storage.AuditEvent{
			SessionID:        sessionID,
			Provider:         provider,
			Model:            model,
			Repo:             repo,
			TokensIn:         uncachedInTokens,
			TokensCacheRead:  cacheReadTokens,
			TokensCacheWrite: cacheWriteTokens,
			TokensOut:        tokensOut,
			CostUSD:          actualCost,
			SavedUSD:         0,
			CacheWastedUSD:   wastedUSD,
			CacheChurnAlert:  churnAlert,
			LatencyMs:        time.Since(start).Milliseconds(),
			Status:           "OK",
			PIIRedactions:    mStats.TotalRedactions,
			PIICategories:    mStats.ByCategory,
		}, sanitizedBody)

		// 5. Unmask Pseudonyms in Response Before Returning to Developer
		finalResp := respBody
		if s.cfg.GDPRMaskingEnabled {
			finalResp = s.masker.UnmaskInbound(respBody)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ZeroTrace-Event-Hash", ev.EventHash)
		w.Header().Set("X-ZeroTrace-Redactions", fmt.Sprintf("%d", mStats.TotalRedactions))
		if churnAlert {
			w.Header().Set("X-ZeroTrace-Cache-Churn", fmt.Sprintf("ALERT:wasted_usd=%.4f", wastedUSD))
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(finalResp))
	}
}

// parseUsageMetrics extracts Anthropic / OpenAI prompt cache metrics from JSON or SSE payloads.
func parseUsageMetrics(respBody string, defaultIn, defaultOut int) (inTok, cacheRead, cacheWrite, outTok int) {
	inTok, outTok = defaultIn, defaultOut
	var payload map[string]any
	if err := json.Unmarshal([]byte(respBody), &payload); err == nil {
		if u, ok := payload["usage"].(map[string]any); ok {
			if v, ok := u["input_tokens"].(float64); ok {
				inTok = int(v)
			} else if v, ok := u["prompt_tokens"].(float64); ok {
				inTok = int(v)
			}
			if v, ok := u["cache_read_input_tokens"].(float64); ok {
				cacheRead = int(v)
			}
			if v, ok := u["cache_creation_input_tokens"].(float64); ok {
				cacheWrite = int(v)
			}
			if v, ok := u["output_tokens"].(float64); ok {
				outTok = int(v)
			} else if v, ok := u["completion_tokens"].(float64); ok {
				outTok = int(v)
			}
		}
	}
	return inTok, cacheRead, cacheWrite, outTok
}

func extractPreview(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 180 {
		return s[:180] + "..."
	}
	return s
}
