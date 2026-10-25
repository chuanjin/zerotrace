package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/chuanjin/zerotrace/agent/internal/breaker"
	"github.com/chuanjin/zerotrace/agent/internal/config"
	"github.com/chuanjin/zerotrace/agent/internal/masker"
	"github.com/chuanjin/zerotrace/agent/internal/proxy"
	"github.com/chuanjin/zerotrace/agent/internal/storage"
)

const version = "0.1.0-mvp"

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "init":
		runInit()
	case "serve", "start":
		runServe()
	case "status", "stats":
		runStatus()
	case "verify":
		runVerify()
	case "export-compliance":
		runExportCompliance()
	case "uninstall":
		runUninstall()
	case "version", "-v", "--version":
		fmt.Printf("zerotrace %s (Built in Gothenburg, Sweden)\n", version)
	default:
		printHelp()
	}
}

func runInit() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│  ZeroTrace Setup — Zero-Knowledge AI & Cloud FinOps Proxy 🇸🇪     │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")
	fmt.Printf("  ✓ Account Number : %s (Mullvad-style anonymous ID)\n", cfg.AccountID)
	fmt.Printf("  ✓ Local Vault    : %s\n", cfg.DataDir)
	fmt.Printf("  ✓ E2EE Key       : %s... (AES-256-GCM local key)\n", cfg.E2EEKey[:12])
	fmt.Printf("  ✓ GDPR Scrubbing : Enabled (SE Personnummer, IBAN, Email, API Keys)\n")
	fmt.Printf("  ✓ Circuit Breaker: Max %d identical retries | $%.2f/session | $%.2f/day\n",
		cfg.Guardrails.MaxIdenticalRetries, cfg.Guardrails.MaxSessionCostUSD, cfg.Guardrails.MaxDailyCostUSD)
	fmt.Println()
	fmt.Println("  To route Claude Code & OpenAI agents through ZeroTrace:")
	fmt.Printf("    export ANTHROPIC_BASE_URL=\"http://%s/anthropic\"\n", cfg.ListenAddr)
	fmt.Printf("    export OPENAI_BASE_URL=\"http://%s/openai\"\n", cfg.ListenAddr)
	fmt.Println()
	fmt.Println("  Run `zerotrace serve` to start the proxy daemon.")
}

func runServe() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	m := masker.New(cfg.HMACSecret)
	b := breaker.New(cfg.Guardrails.MaxSessionCostUSD, cfg.Guardrails.MaxDailyCostUSD, cfg.Guardrails.MaxIdenticalRetries)
	st, err := storage.New(cfg.DataDir, cfg.AccountID, cfg.E2EEKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init storage: %v\n", err)
		os.Exit(1)
	}
	srv := proxy.NewServer(cfg, m, b, st)
	fmt.Printf("🛡️  ZeroTrace Agent %s listening on http://%s (Account: %s)\n", version, cfg.ListenAddr, cfg.AccountID)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "Server stopped: %v\n", err)
		os.Exit(1)
	}
}

func runStatus() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	st, err := storage.New(cfg.DataDir, cfg.AccountID, cfg.E2EEKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading store: %v\n", err)
		os.Exit(1)
	}
	m := st.GetManifest()
	count, head, verifyErr := storage.VerifyAuditChain(cfg.DataDir)
	chainStatus := "✓ VERIFIED (SHA-256 Continuous)"
	if verifyErr != nil {
		chainStatus = "✗ TAMPERED: " + verifyErr.Error()
	}

	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  ZeroTrace Telemetry Summary   Account: %-23s │\n", cfg.AccountID)
	fmt.Println("├──────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│  Total Intercepted Calls : %-37d │\n", m.TotalRequests)
	fmt.Printf("│  Actual Token Spend      : $%-36.4f │\n", m.TotalCostUSD)
	fmt.Printf("│  Saved by Doom-Breaker   : $%-36.4f │\n", m.TotalSavedUSD)
	fmt.Printf("│  Runaway Loops Halted    : %-37d │\n", m.TotalLoopsBlocked)
	fmt.Printf("│  GDPR PII Redactions     : %-37d │\n", m.TotalPIIRedactions)
	fmt.Printf("│  EU AI Act Art.12 Chain  : %-37s │\n", chainStatus)
	if head != "" && len(head) >= 16 {
		fmt.Printf("│  Chain Head Digest       : %s... (%d records)       │\n", head[:16], count)
	}
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")
	if len(m.PIICategoryBreakdown) > 0 {
		fmt.Println("  PII Redactions by Category:")
		for k, v := range m.PIICategoryBreakdown {
			fmt.Printf("    • %-18s : %d\n", k, v)
		}
	}
}

func runVerify() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		os.Exit(1)
	}
	count, head, err := storage.VerifyAuditChain(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Audit Chain Verification FAILED: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("✓ EU AI Act Art. 12 & GDPR Audit Chain Verified: %d events intact.\n", count)
	fmt.Printf("  Latest SHA-256 Digest: %s\n", head)
}

func runExportCompliance() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		os.Exit(1)
	}
	st, err := storage.New(cfg.DataDir, cfg.AccountID, cfg.E2EEKey)
	if err != nil {
		os.Exit(1)
	}
	m := st.GetManifest()
	count, head, verifyErr := storage.VerifyAuditChain(cfg.DataDir)
	report := map[string]any{
		"report_type":            "EU AI Act Article 12 & GDPR Article 32 Compliance Evidence",
		"generated_by":           "ZeroTrace Zero-Knowledge Gateway (Gothenburg, Sweden)",
		"account_id":             cfg.AccountID,
		"generated_at":           m.UpdatedAt,
		"zero_data_egress_proof": "All payloads AES-256-GCM encrypted locally; PII pseudonymized prior to upstream LLM transit.",
		"metrics": map[string]any{
			"total_llm_requests":       m.TotalRequests,
			"total_spend_usd":          m.TotalCostUSD,
			"runaway_spend_prevented":  m.TotalSavedUSD,
			"doom_loops_halted":        m.TotalLoopsBlocked,
			"total_pii_redactions":     m.TotalPIIRedactions,
			"pii_redaction_breakdown":  m.PIICategoryBreakdown,
		},
		"cryptographic_attestation": map[string]any{
			"algorithm":       "SHA-256 Hash Chain",
			"records_audited": count,
			"head_digest":     head,
			"chain_intact":    verifyErr == nil,
		},
	}
	out, _ := json.MarshalIndent(report, "", "  ")
	outPath := filepath.Join(cfg.DataDir, "eu-compliance-report.json")
	_ = os.WriteFile(outPath, out, 0600)
	fmt.Println(string(out))
	fmt.Fprintf(os.Stderr, "\n✓ Saved compliance bundle to %s\n", outPath)
}

func runUninstall() {
	base := config.DefaultBaseDir()
	fmt.Printf("Uninstalling ZeroTrace local configuration at %s...\n", base)
	_ = os.RemoveAll(base)
	fmt.Println("✓ Removed local cache and config. Your S3/R2 buckets remain untouched.")
	fmt.Println("✓ Remember to remove ANTHROPIC_BASE_URL / OPENAI_BASE_URL from your shell profile.")
}

func printHelp() {
	fmt.Println("ZeroTrace — The Mullvad of AI & Cloud Observability (€10/mo flat, Zero Data Egress)")
	fmt.Println("\nUsage:")
	fmt.Println("  zerotrace init               Initialize anonymous Account ID, E2EE keys & guardrails")
	fmt.Println("  zerotrace serve              Start local GDPR-scrubbing & circuit-breaking proxy (:9000)")
	fmt.Println("  zerotrace status             Display real-time spend, saved loop costs & PII redactions")
	fmt.Println("  zerotrace verify             Verify SHA-256 cryptographic integrity of audit logs")
	fmt.Println("  zerotrace export-compliance  Generate EU AI Act Art. 12 & GDPR compliance evidence JSON")
	fmt.Println("  zerotrace uninstall          Cleanly remove local config and restore direct API routing")
}
