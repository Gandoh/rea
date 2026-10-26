# REA Cloud Studio — Commercial SaaS Platform

**REA Cloud Studio** packages REA (`rea-agents` v6.8.0) into a multi-tenant commercial B2B SaaS platform with real-time security posture scoring, CI/CD pull-request release gating, HAR-to-RL `AgentEnv` synthesis, metered REST API keys, and Stripe subscription billing.

---

## Product Suites

1. **AppScope (Electron & JS Attack-Surface X-Ray)**
   - Reconstructs `JavaScriptApplicationGraph` and `JavaScriptSemanticRelationGraph` from `.asar`, `.zip`, or application directories without executing target code.
   - Scores security posture (`0–100`, Grade `A`–`F`), flags missing `event.senderFrame` origin checks paired with `child_process` execution, traces features (`trace_application_feature`), and diffs versions (`compare_application_versions`).

2. **ShipGate (Binary, AI Model & Smart Contract Supply-Chain Gate)**
   - **ELF / PE / APK Binaries:** Dynamic exports, ELF notes, Go/Rust metadata, PE imports/certificates, APK signatures, and symbol-targeted GNU `objdump` x86-64 disassembly.
   - **AI Model Artifacts (`safetensors` / `GGUF`):** Header & full-file SHA-256 digests, PEFT/model metadata declarations, and tensor shape/dtype/offset verification (`inspect_model_artifact` + `inspect_analysis_view`) without loading weights.
   - **Unverified EVM Smart Contracts & Bytecode:** Offline selector/mutability recovery (`inspect_evm_interface`), CPython marshal inspection (`inspect_python_pyc`), and Shannon block-entropy charts (`inspect_byte_entropy`).

3. **RL Factory (HAR-to-AgentEnv Studio)**
   - Compiles recorded `.har` web sessions into runnable Dockerized **AgentEnv** bundles (`inspect_web_network_capture` → `export_environment_bundle`).
   - Boots a **live `serveEnvironment` MCP + `/agentenv` JSON-RPC sandbox** in-process to test synthesized CRUD tools, inspect/reset `rea-state/v1`, grade custom RL task verifiers, and export `.zip` training bundles.

4. **Multi-Tenant Auth, Quotas, Stripe Billing & CI/CD Release Gate**
   - **Auth & Quotas (`studio/server/tenantBilling.mjs`):** `scrypt` password hashing, isolated tenant workspaces, per-tenant revocable `rea_sk_live_…` API keys, and monthly plan quotas (`Free Trial: 5 scans`, `Indie $49/mo: 50 scans`, `ShipGate Team $299/mo: Unlimited CI scans`, `AI Lab $1,499/mo: Unlimited scans + RL builds`) returning `HTTP 402 Payment Required` when exhausted.
   - **Stripe Subscriptions:** Live Stripe Checkout (`POST /api/billing/checkout`) + HMAC-SHA256 verified webhooks (`POST /api/webhooks/stripe`) when `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` are set; automatic interactive Sandbox Checkout mode when unset.
   - **GitHub Actions PR Gate (`studio/ci/`):** Zero-dependency `shipgate-cli.mjs` uploads build artifacts to `/api/v1/*`, writes signed Markdown Audit Dossiers to `$GITHUB_STEP_SUMMARY`, and exits `1` when `release_gate === "BLOCKED"`.

---

## Local Development

```bash
# 1. Build REA core once from repository root
HUSKY=0 npm_config_engine_strict=false npm ci
npm_config_engine_strict=false npm run build:cached

# 2. Start REA Cloud Studio (binds to 0.0.0.0:3080)
PORT=3080 node studio/server/index.mjs
```

## Production Deployment (Docker / Render / Railway / Fly.io)

```bash
# Build production container from repository root
docker build -f studio/Dockerfile -t rea-cloud-studio:latest .

# Run with persistent /data volume and optional live Stripe keys
docker run -d \
  -p 3080:3080 \
  -v rea_studio_data:/data \
  -e STRIPE_SECRET_KEY="sk_live_..." \
  -e STRIPE_WEBHOOK_SECRET="whsec_..." \
  -e REA_BOOTSTRAP_API_KEY="rea_sk_live_..." \
  rea-cloud-studio:latest
```

Configure your Stripe Webhook endpoint in the Stripe Dashboard to point to:
`https://<your-domain>/api/webhooks/stripe` listening to `checkout.session.completed` and `customer.subscription.deleted`.
