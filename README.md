# 🛡️ ZeroTrace

**Privacy Firewall for AI Coding Agents.**  
*Local-First · Reversible De-identification · Zero-Knowledge Cryptographic Audit Trail*  
Built in Gothenburg, Sweden 🇸🇪

---

## What is ZeroTrace?

When developers run autonomous AI coding agents (**Claude Code**, OpenCode, Codex, Cursor), their prompts and tool outputs inevitably contain sensitive data: internal API keys, customer credentials, emails, and EU identifiers (such as Swedish *Personnummer* and IBANs).

**ZeroTrace** acts as a local privacy firewall on your workstation (`127.0.0.1:9000`). It transparently intercepts agent traffic, scrubs sensitive data *before* it leaves your machine, preserves contextual consistency across multi-turn reasoning, and seamlessly restores the original values when responses stream back.

```
┌─────────────────┐       Raw Prompts        ┌───────────────────────┐   Sanitized Stream   ┌────────────────────┐
│ AI Coding Agent │ ───────────────────────> │  ZeroTrace Firewall   │ ───────────────────> │ Upstream Model API │
│  (Claude Code)  │ <─────────────────────── │ (127.0.0.1:9000 local)│ <─────────────────── │ (Anthropic/OpenAI) │
└─────────────────┘      Restored Output     └───────────────────────┘    Masked Response   └────────────────────┘
                                                         │
                                            Local AES-256-GCM Vault
                                            + SHA-256 Audit Hash Chain
```

---

## Core Capabilities

1. **Deterministic Bidirectional Masking**
   - High-entropy pseudonyms (64-bit entropy with collision avoidance) replace API keys, emails, Swedish *Personnummer*, and IBANs.
   - Preserves semantic identity: the same entity within a project maps to the same pseudonym, allowing the LLM to reason accurately without knowing the true underlying secret.
   - **Cross-Chunk SSE Unmasking**: Streams seamlessly de-anonymize tokens even if split across chunk boundaries in real-time.

2. **Transparent Zero-Config Agent Proxy**
   - Works as a drop-in upstream replacement via standard environment variables:
     ```bash
     export ANTHROPIC_BASE_URL="http://127.0.0.1:9000/anthropic"
     export OPENAI_BASE_URL="http://127.0.0.1:9000/openai"
     ```

3. **Tamper-Evident Local Audit Trail**
   - Every outbound interaction is recorded into a local cryptographic `SHA-256` append-only hash chain.
   - Prompts are locally encrypted using client-side `AES-256-GCM`. Zero bytes of raw telemetry touch third-party servers.
   - Offline verification tool (`zerotrace verify`) verifies the entire hash chain to detect any tampering, reordering, insertion, or deletion.

4. **Auxiliary Agent Guardrails**
   - **Runaway Doom-Loop Breaker**: Detects repeated identical failure loops and returns `HTTP 429 Retry-After`.
   - **Two-Phase Budget Reconciliation**: Tracks estimated token reservations and reconciles against actual stream usage metrics, releasing budget on failed requests.

---

## Quickstart

### 1. Install
```bash
curl -fsSL https://raw.githubusercontent.com/chuanjin/zerotrace/main/install.sh | sh
```
*Or build from source:*
```bash
cd agent && go build -o zerotrace ./cmd/zerotrace
```

### 2. Initialize
```bash
zerotrace init
```
Generates your anonymous 16-digit Account ID, local `AES-256-GCM` encryption key, and configuration under `~/.zerotrace/config.json`.

### 3. Route Claude Code
Start the local firewall:
```bash
zerotrace serve
```

In your terminal or project workspace, point Claude Code to the local proxy:
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:9000/anthropic"
claude
```

### 4. Verify Audit Integrity & Inspect Logs
```bash
zerotrace status             # Summary of active redactions, requests, and budget
zerotrace verify             # Cryptographic verification of the SHA-256 audit chain
zerotrace export-compliance  # Export verifiable audit bundle
```

---

## Protection Scope & Boundaries

* **What ZeroTrace protects**: Targeted pattern-based identifiers including secret keys (`sk-ant-...`, `sk-...`, `AKIA...`, `ghp_...`), email addresses, Swedish Personnummer (10 and 12-digit formats), and European IBANs (both compact and formatted with spaces).
* **Technical Privacy vs. Legal Compliance**: Automated pattern matching provides technical privacy defense-in-depth and verifiable logging. It cannot guarantee 100% detection of arbitrary unstructured confidential information, and does not automatically fulfill entire organizational GDPR or EU regulatory mandates on its own.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for full details.
