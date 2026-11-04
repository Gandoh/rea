# REA AppScope X-Ray — provider-independent deployment runbook

This pack contains **templates and documentation only**. Nothing here deploys
anything, activates billing, or touches the Bah Digital Solutions website
(`website/`). All steps are manual and under your control.

## 1. Minimum requirements (measured on the sandbox preview)

| Resource | Minimum | Notes |
|---|---|---|
| RAM | **1 GB** (2 GB recommended) | Measured Studio process ≈ 400 MB RSS + ≈ 100 MB analysis worker |
| CPU | **1 vCPU** | Scans are single-tenant and CPU-bound; 2 vCPU if concurrent use |
| Storage | **20 GB boot disk + a separate persistent data volume ≥ 5 GB** | OS + Node + build artifacts on boot disk; SQLite + evidence + uploads on the data volume |
| Persistent disk | **Required** | `REA_STUDIO_DATA_DIR` must live on durable storage — the server refuses to boot in production if it resolves under `/tmp` |
| HTTPS | **Required in production** | `PUBLIC_BASE_URL` must be `https://`. Free options: Cloudflare Tunnel (free, no open ports) or any TLS reverse proxy |
| OS | Linux x86_64 or arm64, Node.js **24.x** (engines: `^22.23.4 || ^24.22.1 || >=26.12.1`) | `studio/Dockerfile` (`node:24.22.1-bookworm-slim`) is also provided for container hosts |
| Network | Inbound 443 (or none, if using Cloudflare Tunnel), outbound 443 for npm/deps | |

Free-tier fit: a single always-on VM with ≥1 GB RAM and a persistent disk runs
the complete app (real X-Ray scans, MCP, auth, SQLite) at $0 on providers whose
signup accepts your country and that offer an always-free tier with persistent
storage. Cloudflare Tunnel + Access (free, ≤50 users) gives you HTTPS and
email-allowlist access from your phone without opening ports. If no free VM
provider is available to you, an always-on local machine (e.g. in Freetown)
behind a free Cloudflare Tunnel is a valid $0 origin.

## 2. Prepare the host

```bash
# Any always-on Linux host with a persistent disk (VM or local machine):
sudo mkdir -p /data/rea-studio /var/tmp/rea-studio-runtime
# install Node 24.x, git, then:
git clone <your-repo-url> rea && cd rea
git checkout <branch>   # e.g. the PR branch you validated
npm ci                  # locked dependencies only
npm ci --prefix studio
npm run build           # required: dist/ must exist before starting
```

## 3. Configure environment

```bash
cp studio/.env.production.example studio/.env.production
# edit studio/.env.production: set PUBLIC_BASE_URL to your https origin,
# CORS_ALLOWED_ORIGINS, REA_STUDIO_DATA_DIR=/data/rea-studio, HOST=127.0.0.1
# Leave all KELVIQ_*/STRIPE_* keys EMPTY (billing stays disabled).
```

In `NODE_ENV=production` the server **fails fast at startup** with clear errors
if `PUBLIC_BASE_URL` is missing/not-https, `CORS_ALLOWED_ORIGINS` contains an
unsafe entry, `REA_STUDIO_DATA_DIR` is missing or under `/tmp`, `PORT` is
invalid, or `ALLOW_SANDBOX_BILLING=true`. See
`studio/server/configValidation.mjs`.

## 4. Run as a service (systemd)

```bash
sudo cp studio/deploy/rea-studio.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rea-studio
systemctl status rea-studio
curl -s http://127.0.0.1:3080/api/health   # expect {"ok":true,...}
```

## 5. Expose it with HTTPS + private access (Cloudflare, free)

Uses **your existing Cloudflare account** — no paid plan needed.

1. Add your domain to Cloudflare (free plan) and point its nameservers at Cloudflare.
2. On the host: `cloudflared tunnel login` then create a tunnel, or use
   `studio/deploy/cloudflared-config.yml` as the template:
   `cloudflared tunnel run --config studio/deploy/cloudflared-config.yml`
3. Route a hostname (e.g. `studio.yourdomain.com`) to `http://127.0.0.1:3080`.
4. In Zero Trust → Access, add a policy on that hostname allowing **only your
   email** (email one-time PIN). Free for up to 50 users. This makes the app
   reachable from your phone but not by the public — unlike a raw port-forward.
5. Set `PUBLIC_BASE_URL=https://studio.yourdomain.com` and restart the service.

Alternative: any TLS reverse proxy (nginx/Caddy) with a certificate, if you
prefer not to route traffic through Cloudflare.

## 6. Verify from outside (dependency-free smoke test)

```bash
node studio/scripts/smoke-external.mjs https://studio.yourdomain.com
```

The script uses only Node built-ins, creates a **disposable** account
(`rea-smoke-<timestamp>@example.test` style, random password), and refuses to
run if the target reports live billing keys configured. It checks:
`/api/health` → register → login → CSRF token → one **real** X-Ray scan of the
bundled sample (`acme-desktop-v1`). It never calls any billing/webhook
endpoint, so it cannot trigger payments. Exit code 0 = all passed.

## 7. Operations

- Backups: `npm run db:backup --prefix studio` (SQLite backup scripts, offline-safe).
- Logs: `journalctl -u rea-studio -f`. Startup logs print a **redacted** config
  summary (key presence booleans only, never values).
- Upgrades: pull, `npm ci`, `npm ci --prefix studio`, `npm run build`, restart,
  re-run the smoke test.
- Firewall: with Cloudflare Tunnel you can close all inbound ports except SSH.

## 8. What this pack deliberately does NOT do

- No deployment, no paid plans, no billing activation, no public launch.
- No changes to `website/` (Bah Digital Solutions) or to the scanning engine —
  scans remain fully real.
- `render.yaml` / `railway.json` in this repo target **paid** plans; do not use
  them for a $0 setup.
