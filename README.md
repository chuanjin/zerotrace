# 🛡️ ZeroTrace

**The Mullvad of AI & Cloud Observability.**  
*Zero-Knowledge GDPR Proxy · Active Doom-Loop Circuit Breaker · BYOC S3 Parquet + DuckDB-Wasm Console*  
Built in Gothenburg, Sweden 🇸🇪

---

## Why ZeroTrace?

Engineering teams running AI coding agents (**Claude Code, Codex, OpenCode, Cursor**) and production LLM pipelines face three painful realities in 2026:

1. **Silent Bill Spikes & Doom Loops**: Agents get stuck in retry loops or bust 100K-token prompt caches (`cache_creation` churn), burning hundreds of dollars overnight with zero merged PRs.
2. **EU GDPR & AI Act Blockers**: Sending customer PII (emails, Swedish *Personnummer*, IBANs, API keys) to US-hosted observability SaaS violates strict EU data-residency policies—while enterprise gateways charge $500–$1,000+/month for EU compliance.
3. **Heavyweight Self-Hosting Fatigue**: Teams want cost and audit visibility without babysitting a multi-container ClickHouse + Postgres + Redis + Kafka cluster.

**ZeroTrace** solves all three with a single `<11MB` Go binary and a zero-backend WebAssembly console:
- **Zero bytes touch our servers**: Telemetry is AES-256-GCM encrypted and written as columnar **Apache Parquet v2** directly to local disk or **your own S3 / Cloudflare R2 bucket**.
- **Deterministic bidirectional GDPR masking**: Sensitive PII and credentials are swapped with deterministic HMAC pseudonyms *before* leaving your machine, and seamlessly unmasked (even across chunked SSE boundaries) on the way back.
- **Active Circuit Breaker**: Hard-stops runaway agent retry loops (`HTTP 429 Retry-After`) and alerts on prompt cache churn.
- **EU AI Act Article 12 Tamper-Evident Chain**: Every event is linked via a continuous `SHA-256` hash chain, verifiable offline at any time.

---

## Architecture

```text
┌──────────────────────┐       1. Intercept & Scrub PII        ┌─────────────────────────┐
│ Claude Code / Cursor │ ────────────────────────────────────► │   zerotrace-agent (Go)  │
│   OpenAI / SDKs      │ ◄──────────────────────────────────── │   localhost:9000        │
└──────────────────────┘    4. Cross-Chunk SSE Unmasking       └───────────┬─────────────┘
                                                                           │
                            ┌──────────────────────────────────────────────┼──────────────────────────────────────────┐
                            │                                              │ 2. Forward Sanitized Prompt              │
                            ▼ 3. AES-256-GCM + SHA-256 Chain               ▼    (Zero Raw PII Leaves Machine)         │
              ┌───────────────────────────┐                  ┌───────────────────────────┐                            │
              │ Your S3 / Cloudflare R2   │                  │ Anthropic / OpenAI / LLM  │                            │
              │ (Apache Parquet v2)       │                  └───────────────────────────┘                            │
              └─────────────┬─────────────┘                                                                           │
                            │ 5. Direct HTTP Range Read (CORS)                                                        │
                            ▼                                                                                         │
              ┌───────────────────────────┐                                                                           │
              │ Browser Console (Static)  │  ◄── DuckDB-Wasm SQL + WebCrypto AES-256-GCM Decryption (100% Client-Side)│
              └───────────────────────────┘                                                                           │
```

---

## 30-Second Quickstart

### 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/chuanjin/zerotrace/main/install.sh | sh
```

*(Or build from source with Go 1.22+: `./install.sh`)*

### 2. Initialize Anonymous Account & Daemon

```bash
zerotrace init
zerotrace daemon install   # Starts background service (systemd --user on Linux / launchd on macOS)
zerotrace hook install     # Injects proxy exports into ~/.zshrc / ~/.bashrc automatically
```

Generates a Mullvad-style 16-digit anonymous Account ID, a local 256-bit `AES-256-GCM` encryption key, and default budget/loop guardrails in `~/.zerotrace/config.json`.

### 3. Start Hacking (Claude Code / Cursor / OpenAI)

Open a new shell or run `source ~/.zshrc`. All LLM calls now flow through your local zero-knowledge proxy:
- **Claude Code**: Works out of the box with `ANTHROPIC_BASE_URL="http://127.0.0.1:9000/anthropic"`.
- **OpenAI / Cursor**: Routed via `OPENAI_BASE_URL="http://127.0.0.1:9000/openai"`.

### 4. Inspect Spend, Saved Loop Costs & Verify Audit Chain

```bash
zerotrace status             # Terminal summary table (spend, loop savings, PII counts)
zerotrace verify             # Cryptographic SHA-256 chain verification
zerotrace export-compliance  # Export EU AI Act Art. 12 & GDPR compliance bundle
```

---

## Zero-Knowledge Web Console (DuckDB-Wasm)

Open `web/index.html` in your browser. It connects to your local agent at `http://127.0.0.1:9000` (or your remote S3 bucket):
- **DuckDB-Wasm in browser**: Queries `telemetry.parquet` directly in browser memory without sending a single byte to our servers.
- **Client-Side AES Decryption**: Paste your local key from `~/.zerotrace/config.json` to decrypt prompts on your machine.
- **1-Click PDF**: Print an audit-ready compliance document.

---

## Optional: BYOC S3 / Cloudflare R2 Sync

Sync your encrypted columnar Parquet logs directly to your own object storage bucket with one command (automatically provisions bucket & browser `Range` CORS headers):

```bash
zerotrace s3-setup \
  --endpoint https://<account>.r2.cloudflarestorage.com \
  --bucket zerotrace-eu-vault \
  --access-key <R2_ACCESS_KEY> \
  --secret-key <R2_SECRET_KEY>
```

Open `web/index.html` in any modern browser to query `telemetry.parquet` in-memory via **DuckDB-Wasm**, inspect AES-256-GCM encrypted prompts locally using your key, and export an **EU AI Act Article 12 / GDPR Article 32** compliance PDF.

---

## Clean Uninstall

ZeroTrace leaves no zombie configurations behind:

```bash
zerotrace uninstall
```

---

## License

Apache License 2.0 — Built in Gothenburg, Sweden.
