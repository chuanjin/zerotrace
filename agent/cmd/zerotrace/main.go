package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/chuanjin/zerotrace/agent/internal/breaker"
	"github.com/chuanjin/zerotrace/agent/internal/config"
	"github.com/chuanjin/zerotrace/agent/internal/daemon"
	"github.com/chuanjin/zerotrace/agent/internal/hook"
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
	case "daemon":
		runDaemon()
	case "hook":
		runHook()
	case "s3-setup":
		runS3Setup()
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
	fmt.Printf("  ✓ Account Number : %s (Anonymous 16-digit ID)\n", cfg.AccountID)
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
	if cfg.Storage.Mode == "s3" {
		s3c := storage.NewS3Client(cfg.Storage)
		st.SetS3Client(s3c)
		fmt.Printf("☁️  BYOC S3/R2 Direct Parquet Sync Enabled -> %s/%s\n", cfg.Storage.Endpoint, cfg.Storage.Bucket)
	}
	srv := proxy.NewServer(cfg, m, b, st)
	fmt.Printf("🛡️  ZeroTrace Agent %s listening on http://%s (Account: %s)\n", version, cfg.ListenAddr, cfg.AccountID)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "Server stopped: %v\n", err)
		os.Exit(1)
	}
}

func runS3Setup() {
	cfg, err := config.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	// Accept flags or environment variables for non-interactive setup
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--endpoint":
			if i+1 < len(os.Args) {
				cfg.Storage.Endpoint = os.Args[i+1]
				i++
			}
		case "--bucket":
			if i+1 < len(os.Args) {
				cfg.Storage.Bucket = os.Args[i+1]
				i++
			}
		case "--region":
			if i+1 < len(os.Args) {
				cfg.Storage.Region = os.Args[i+1]
				i++
			}
		case "--access-key":
			if i+1 < len(os.Args) {
				cfg.Storage.AccessKey = os.Args[i+1]
				i++
			}
		case "--secret-key":
			if i+1 < len(os.Args) {
				cfg.Storage.SecretKey = os.Args[i+1]
				i++
			}
		}
	}
	if cfg.Storage.Endpoint == "" {
		fmt.Fprintln(os.Stderr, "Usage: zerotrace s3-setup --endpoint <https://...> --bucket <name> --access-key <key> --secret-key <secret> [--region auto]")
		os.Exit(1)
	}
	cfg.Storage.Mode = "s3"
	if cfg.Storage.Region == "" {
		cfg.Storage.Region = "auto"
	}
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed saving config: %v\n", err)
		os.Exit(1)
	}
	s3c := storage.NewS3Client(cfg.Storage)
	if err := s3c.EnsureBucketAndCORS(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ S3/R2 provisioning error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Configured BYOC S3/R2 bucket %q at %s\n", cfg.Storage.Bucket, cfg.Storage.Endpoint)
	fmt.Println("✓ Applied DuckDB-Wasm browser CORS policy (GET/HEAD Range headers exposed)")
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
	fmt.Printf("│  Cache Churn Wasted      : $%-16.4f (%2d churn alerts) │\n", m.TotalCacheWastedUSD, m.TotalCacheChurns)
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

func runHook() {
	sub := "install"
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	cfg, err := config.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	switch sub {
	case "install":
		updated, err := hook.Install("", cfg.ListenAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Hook install error: %v\n", err)
			os.Exit(1)
		}
		for _, p := range updated {
			fmt.Printf("✓ Injected ZeroTrace proxy exports into %s\n", p)
		}
		fmt.Println("  Run `source ~/.zshrc` (or open a new terminal) to activate.")
	case "uninstall", "remove":
		cleaned, err := hook.Uninstall("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Hook uninstall error: %v\n", err)
			os.Exit(1)
		}
		for _, p := range cleaned {
			fmt.Printf("✓ Removed ZeroTrace proxy exports from %s\n", p)
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: zerotrace hook [install|uninstall]")
		os.Exit(1)
	}
}

func runDaemon() {
	sub := "install"
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	switch sub {
	case "install", "enable":
		path, err := daemon.Install("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Daemon install error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ ZeroTrace background daemon installed and started: %s\n", path)
	case "uninstall", "disable", "stop":
		path, err := daemon.Uninstall()
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Daemon uninstall error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ ZeroTrace background daemon stopped and removed: %s\n", path)
	default:
		fmt.Fprintln(os.Stderr, "Usage: zerotrace daemon [install|uninstall]")
		os.Exit(1)
	}
}

func runUninstall() {
	_, _ = daemon.Uninstall()
	fmt.Println("✓ Stopped and removed system background service.")
	cleaned, _ := hook.Uninstall("")
	for _, p := range cleaned {
		fmt.Printf("✓ Stripped ZeroTrace hook from %s\n", p)
	}
	base := config.DefaultBaseDir()
	fmt.Printf("Uninstalling ZeroTrace local configuration at %s...\n", base)
	_ = os.RemoveAll(base)
	fmt.Println("✓ Removed local cache and config. Your S3/R2 buckets remain untouched.")
}

func printHelp() {
	fmt.Println("ZeroTrace — Zero-Knowledge AI Gateway & FinOps Controller")
	fmt.Println("\nUsage:")
	fmt.Println("  zerotrace init               Initialize anonymous Account ID, E2EE keys & guardrails")
	fmt.Println("  zerotrace daemon install     Register and start background service (systemd/launchd)")
	fmt.Println("  zerotrace daemon uninstall   Stop and remove background service")
	fmt.Println("  zerotrace hook install       Automatically inject proxy exports into ~/.zshrc / ~/.bashrc")
	fmt.Println("  zerotrace hook uninstall     Cleanly strip proxy exports from shell profiles")
	fmt.Println("  zerotrace s3-setup           Configure BYOC S3/R2 bucket and DuckDB-Wasm CORS policy")
	fmt.Println("  zerotrace serve              Start local GDPR-scrubbing & circuit-breaking proxy (:9000)")
	fmt.Println("  zerotrace status             Display real-time spend, saved loop costs & PII redactions")
	fmt.Println("  zerotrace verify             Verify SHA-256 cryptographic integrity of audit logs")
	fmt.Println("  zerotrace export-compliance  Generate EU AI Act Art. 12 & GDPR compliance evidence JSON")
	fmt.Println("  zerotrace uninstall          Cleanly remove daemon, hooks, local config and restore direct API routing")
}
