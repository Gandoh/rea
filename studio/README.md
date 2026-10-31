# REA Cloud Studio & AlphaShield — Commercial SaaS Suite

**REA Cloud Studio** + **AlphaShield by Gandoh Bah Ai** package REA (`rea-agents` v6.8.0) and real-time market intelligence into two ready-to-monetize SaaS products backed by **Kelviq Merchant-of-Record** (`@kelviq/node-sdk`) and Stripe billing:

- **AlphaShield (`/alphashield` · `studio/alphashield/index.html`)** — High-conversion B2C/Prosumer Live Crypto Market Terminal + On-Chain EVM Smart Contract Rug/Honeypot Scanner + SafeAPK/Wallet Drainer File Gate + 1-Tap Viral X/Telegram/WhatsApp Alert Cards (`$19/mo` Pro Trader · `$49/mo` Whale & Alpha Group via Kelviq).
- **REA Cloud Studio (`/` · `studio/public/index.html`)** — B2B Developer & AI Lab Security Platform with Electron/JS Attack-Surface X-Ray, ShipGate CI/CD PR Release Gate, and HAR-to-RL `AgentEnv` Synthesis.

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

4. **Multi-Tenant Auth, Quotas, Stripe/Kelviq Billing & CI/CD Release Gate**
   - **Auth & Quotas (`studio/server/tenantBilling.mjs`):** `scrypt` password hashing, `HttpOnly; Secure; SameSite=Lax` sessions + CSRF tokens, isolated tenant workspaces, per-tenant revocable `rea_sk_live_…` API keys scoped strictly to `/api/v1/*`, and server-enforced Studio + AlphaShield scan quotas returning `HTTP 402 Payment Required` when exhausted.
   - **Stripe & Kelviq Subscriptions:** Live Kelviq MoR (`POST /api/kelviq/checkout`, `POST /api/webhooks/kelviq`) and Stripe Checkout (`POST /api/billing/checkout`, `POST /api/webhooks/stripe`).
   - **GitHub Actions PR Gate (`studio/ci/`):** Zero-dependency `shipgate-cli.mjs` uploads build artifacts to `/api/v1/*`, writes signed Markdown Audit Dossiers to `$GITHUB_STEP_SUMMARY`, and exits `1` when `release_gate === "BLOCKED"`.

---

## Local Development

Requires Node.js matching `.nvmrc` (`24.22.1`, or `^22.23.4 || ^24.22.1 || >=26.12.1`).

```bash
# 1. Build REA core & install Studio dependencies deterministically
HUSKY=0 npm ci
npm run build:cached
HUSKY=0 npm ci --prefix studio

# 2. (Optional) Configure local settings in studio/.env.local
cp studio/.env.example studio/.env.local

# 3. Start REA Cloud Studio + AlphaShield (/alphashield) on 0.0.0.0:3080
REA_STUDIO_DATA_DIR=./studio/data PORT=3080 node studio/server/index.mjs
```

---

## Persistent Storage, Backups & Disaster Recovery (REQUIRED in Production)

`studio.sqlite` stores tenant accounts, sessions, API key digests, subscription entitlements, license seat bindings (`license_activations`), webhook replay ledgers (`processed_webhook_ids`), and redeemed USDT transaction hashes (`consumed_tx_hashes`).

- **Persistent Volume Requirement:** In `NODE_ENV=production`, `studio/server/index.mjs` **refuses to start** if `REA_STUDIO_DATA_DIR` is unset or resolves inside `/tmp` (`/tmp`, `/var/tmp`, `/private/tmp`). Mount a persistent encrypted disk at `/data` (preconfigured in `studio/render.yaml` and `studio/Dockerfile`) or set `REA_STUDIO_DATA_DIR` to durable host storage (e.g. `/var/lib/rea-studio/data`).
- **Online Point-in-Time Backup (`VACUUM INTO`):** Safe to run while the server is serving live WAL traffic:
  ```bash
  npm run db:backup --prefix studio -- /data/studio.sqlite /backups/studio-$(date -u +%Y%m%dT%H%M%SZ).sqlite
  ```
- **Verify Backup Integrity & Schema:**
  ```bash
  npm run db:verify --prefix studio -- /backups/studio-20261030T000000Z.sqlite
  ```
- **Atomic Restore (stop the Studio process first):**
  ```bash
  npm run db:restore --prefix studio -- /backups/studio-20261030T000000Z.sqlite /data/studio.sqlite
  ```

---

## Kelviq Merchant-of-Record Setup (`Gandoh Bah Ai`)

1. In [app.kelviq.com](https://app.kelviq.com) (`Gandoh Bah Ai`), create plans matching `studio/.env.example`:
   - `alphashield-pro` — **$19/month** (`$159/year`)
   - `alphashield-whale` — **$49/month** (`$399/year`)
   - `rea-ai-lab` — **$1,499/month**
2. Set `PUBLIC_BASE_URL`, `TRUSTED_PROXY_IPS`, `KELVIQ_SERVER_API_KEY`, `KELVIQ_CLIENT_API_KEY`, `KELVIQ_ENV=production`, and `KELVIQ_WEBHOOK_SECRET` in Railway / Render.
3. Point your Kelviq Webhook URL to `https://<your-domain>/api/webhooks/kelviq`.

## Production Deployment (Docker / Render / Railway / Fly.io)

```bash
# Build production container from repository root
docker build -f studio/Dockerfile -t rea-cloud-studio:latest .

# Run with persistent /data volume, canonical PUBLIC_BASE_URL, and reverse-proxy settings
docker run -d \
  -p 3080:3080 \
  -v rea_studio_data:/data \
  -e NODE_ENV="production" \
  -e REA_STUDIO_DATA_DIR="/data" \
  -e PUBLIC_BASE_URL="https://studio.example.com" \
  -e TRUSTED_PROXY_IPS="10.0.0.1" \
  -e STRIPE_SECRET_KEY="sk_live_..." \
  -e STRIPE_WEBHOOK_SECRET="whsec_..." \
  -e REA_BOOTSTRAP_API_KEY="rea_sk_live_replace_with_20plus_char_secret" \
  rea-cloud-studio:latest
```

Configure your Stripe Webhook endpoint in the Stripe Dashboard to point to:
`https://<your-domain>/api/webhooks/stripe` listening to `checkout.session.completed` and `customer.subscription.deleted`.
