# 🛡️ ZeroTrace

**The Zero-Knowledge AI Gateway & FinOps Controller.**  
*Zero-Knowledge GDPR Proxy · Active Doom-Loop Circuit Breaker · BYOC S3 Parquet + DuckDB-Wasm Console*  
Built in Gothenburg, Sweden 🇸🇪

---

## Why ZeroTrace?

Engineering teams running AI coding agents (**Claude Code, Cursor, OpenCode, Codex**) and production LLM pipelines face three painful realities in 2026:

1. **Silent Bill Spikes & Doom Loops**: Agents get stuck in retry loops or bust 100K-token prompt caches (`cache_creation` churn), burning hundreds of dollars overnight with zero merged PRs.
2. **EU GDPR & AI Act Blockers**: Sending customer PII (emails, Swedish *Personnummer*, IBANs, API keys) to US-hosted observability SaaS violates strict EU data-residency policies—while enterprise gateways charge $500–$1,000+/month for EU compliance.
3. **Heavyweight Self-Hosting Fatigue**: Teams want cost and audit visibility without babysitting a multi-container ClickHouse + Postgres + Redis + Kafka cluster.

**ZeroTrace** solves all three with a single `<11MB` Go binary and a zero-backend WebAssembly console:

- **Zero bytes touch our servers**: Telemetry is AES-256-GCM encrypted and written as columnar **Apache Parquet v2** directly to local disk or **your own S3 / Cloudflare R2 bucket**.
- **Deterministic bidirectional GDPR masking**: Sensitive PII and credentials are swapped with deterministic HMAC pseudonyms *before* leaving your machine, and seamlessly unmasked (even across chunked SSE boundaries) on the way back.
- **Active Circuit Breaker**: Hard-stops runaway agent retry loops (`HTTP 429 Retry-After`) and alerts on prompt cache churn.
- **EU AI Act Article 12 Tamper-Evident Chain**: Every event is linked via a continuous `SHA-256` hash chain, verifiable offline at any time.

---

## Quickstart

### 1. Install
```bash
curl -fsSL https://raw.githubusercontent.com/chuanjin/zerotrace/main/install.sh | sh
```

### 2. Initialize
```bash
zerotrace init
zerotrace daemon install   # Starts background service (systemd --user / launchd)
zerotrace hook install     # Injects proxy exports into ~/.zshrc / ~/.bashrc
```

Generates a privacy-first 16-digit anonymous Account ID, a local 256-bit `AES-256-GCM` encryption key, and guardrails in `~/.zerotrace/config.json`.

### 3. Start Hacking
All LLM calls now flow through your local zero-knowledge proxy:
- **Claude Code**: Works natively via `ANTHROPIC_BASE_URL`.
- **OpenAI / Cursor**: Routed via `OPENAI_BASE_URL`.

### 4. Inspect Spend & Verify Compliance
```bash
zerotrace status             # Real-time summary table (spend, loop savings, PII counts)
zerotrace verify             # Cryptographic SHA-256 chain verification
zerotrace export-compliance  # Export EU AI Act Art. 12 & GDPR bundle
```

---

## Zero-Knowledge Web Console (DuckDB-Wasm)

Open `web/index.html` in your browser. It connects to your local agent at `http://127.0.0.1:9000` (or your remote S3 bucket):
- **DuckDB-Wasm in-browser SQL**: Queries `telemetry.parquet` directly in browser memory without sending a single byte to our servers.
- **Client-Side Decryption**: Paste your local key from `~/.zerotrace/config.json` to decrypt prompts on your machine.
- **Audit Reports**: Export compliance bundles in JSON/PDF locally.

---

## Community vs. Team Edition

| Feature | Community (OSS) | Team Edition (SaaS / Enterprise) |
| :--- | :---: | :---: |
| **Proxy & Masking** | ✅ Unlimited | ✅ Unlimited |
| **Circuit Breaker** | ✅ Unlimited | ✅ Unlimited |
| **SHA-256 Audit Chain** | ✅ Unlimited | ✅ Unlimited |
| **DuckDB Web Console** | ✅ Local | ✅ Local + S3 Cloud Sync |
| **Compliance Export PDF** | ❌ | ✅ |
| **Slack / Teams Alerts** | ❌ | ✅ |
| **Multi-Node Team Dashboard** | ❌ | ✅ |

For team-wide FinOps governance, audit aggregation, and enterprise compliance reporting, see [zerotrace.eu/pricing](https://zerotrace.eu/pricing).

---

## License & Privacy
- **Apache License 2.0**.
- ZeroTrace is developed in Gothenburg, Sweden, adhering to the highest standards of user privacy. No telemetry, no usage tracking, no data egress.
