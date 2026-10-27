import { createServer as createHttpServer } from "node:http";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ReaStudioEngine } from "./reaEngine.mjs";
import { KelviqBillingBridge, loadDotEnvFiles } from "./kelviqBilling.mjs";
import { renderAuditMarkdown } from "./riskScoring.mjs";
import { ensureStudioSamples } from "./sampleFactory.mjs";
import { PLANS, TenantBillingStore } from "./tenantBilling.mjs";
import { zipDirectory } from "./zipBuilder.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const STUDIO_ROOT = resolve(__dirname, "..");
const PUBLIC_DIR = join(STUDIO_ROOT, "public");
const ALPHASHIELD_DIR = join(STUDIO_ROOT, "alphashield");
const REPO_ROOT = resolve(STUDIO_ROOT, "..");

loadDotEnvFiles([STUDIO_ROOT, REPO_ROOT]);

const RUNTIME_DIR = process.env.REA_STUDIO_RUNTIME_DIR || "/tmp/rea-studio-runtime";
const DATA_DIR = process.env.REA_STUDIO_DATA_DIR || join(RUNTIME_DIR, "data");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024; // 32 MiB

const MIME_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
});

mkdirSync(RUNTIME_DIR, { recursive: true });
mkdirSync(DATA_DIR, { recursive: true });
const samples = ensureStudioSamples(REPO_ROOT, RUNTIME_DIR);
const engine = new ReaStudioEngine(REPO_ROOT, RUNTIME_DIR);
const billing = new TenantBillingStore(join(DATA_DIR, "tenant-store.json"), {
  bootstrapApiKey: process.env.REA_BOOTSTRAP_API_KEY,
});
const kelviq = new KelviqBillingBridge();

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-headers":
      "content-type, authorization, x-filename, x-studio-session, stripe-signature, webhook-id, webhook-timestamp, webhook-signature",
    "access-control-allow-methods": "GET, POST, OPTIONS",
  });
  res.end(body);
}

function readBodyBuffer(req, maxBytes = MAX_UPLOAD_BYTES) {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        rejectPromise(new Error(`Payload exceeds ${maxBytes} byte limit`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolvePromise(Buffer.concat(chunks)));
    req.on("error", rejectPromise);
  });
}

async function readJsonBody(req) {
  const buf = await readBodyBuffer(req, 8 * 1024 * 1024);
  if (buf.length === 0) return {};
  return JSON.parse(buf.toString("utf8"));
}

function sanitizeFilename(name) {
  const clean = basename(String(name || "artifact.bin")).replace(/[^a-zA-Z0-9._-]+/g, "_");
  return clean || "artifact.bin";
}

function extractZipSafely(zipPath, destDir) {
  mkdirSync(destDir, { recursive: true });
  execFileSync(
    "python3",
    [
      "-c",
      `import os, sys, zipfile
zpath, out = sys.argv[1], os.path.realpath(sys.argv[2])
with zipfile.ZipFile(zpath, 'r') as zf:
    for info in zf.infolist():
        target = os.path.realpath(os.path.join(out, info.filename))
        if not (target == out or target.startswith(out + os.sep)):
            raise ValueError("Unsafe zip member path")
        if info.is_dir():
            os.makedirs(target, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())
`,
      zipPath,
      destDir,
    ],
    { stdio: "pipe" },
  );
}

function resolvePublicOrigin(req) {
  const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || `127.0.0.1:${PORT}`)
    .split(",")[0]
    .trim();
  return `${proto}://${host}`;
}

const server = createHttpServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-headers":
          "content-type, authorization, x-filename, x-studio-session, stripe-signature",
        "access-control-allow-methods": "GET, POST, OPTIONS",
      });
      res.end();
      return;
    }

    const url = new URL(req.url || "/", "http://studio.local");
    const pathname = url.pathname;

    // -----------------------------------------------------------------------
    // System, Health & CI Script Distribution Endpoints
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/health") {
      await engine.init();
      sendJson(res, 200, {
        ok: true,
        status: "healthy",
        rea_version: "6.8.0",
        mcp_tools: engine.toolCount,
        uptime_sec: Math.round(process.uptime()),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/ci/shipgate-cli.mjs") {
      const cliBytes = readFileSync(join(STUDIO_ROOT, "ci/shipgate-cli.mjs"));
      res.writeHead(200, {
        "content-type": "application/javascript; charset=utf-8",
        "content-length": cliBytes.length,
        "content-disposition": 'attachment; filename="shipgate-cli.mjs"',
      });
      res.end(cliBytes);
      return;
    }

    if (req.method === "GET" && pathname === "/api/ci/github-action.yml") {
      const ymlBytes = readFileSync(join(STUDIO_ROOT, "ci/github-action-workflow.yml"));
      res.writeHead(200, {
        "content-type": "text/yaml; charset=utf-8",
        "content-length": ymlBytes.length,
        "content-disposition": 'attachment; filename="rea-shipgate.yml"',
      });
      res.end(ymlBytes);
      return;
    }

    // -----------------------------------------------------------------------
    // Stripe Signed Webhook Endpoint (raw body required for HMAC-SHA256)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/webhooks/stripe") {
      const rawBuf = await readBodyBuffer(req, 2 * 1024 * 1024);
      const sig = req.headers["stripe-signature"] || "";
      const handled = billing.verifyAndHandleStripeWebhook(rawBuf, sig);
      sendJson(res, handled.ok ? 200 : handled.status || 400, handled);
      return;
    }

    if (req.method === "POST" && pathname === "/api/webhooks/kelviq") {
      const rawBuf = await readBodyBuffer(req, 2 * 1024 * 1024);
      try {
        await kelviq.init();
        const event = kelviq.verifyAndParseWebhook(rawBuf, req.headers);
        const type = String(event?.type || event?.event || "");
        const data = event?.data || event?.object || event || {};
        const meta = data?.metadata || event?.metadata || {};
        const tenantId = meta.tenant_id || data.customerId || data.customer_id;
        const planRaw = meta.plan_id || data.planIdentifier || data?.plan?.identifier;

        if (/checkout\.completed|subscription\.(created|activated|updated)/i.test(type) && tenantId) {
          const mappedPlan = PLANS[planRaw] ? planRaw : kelviq.internalPlanFromKelviq(planRaw);
          const provisioned = billing.applyPlanProvisioning(tenantId, mappedPlan, {
            source: "kelviq_webhook",
          });
          sendJson(res, 200, { ok: true, event_type: type, provisioned });
          return;
        }
        if (/subscription\.(cancelled|canceled|expired)/i.test(type) && tenantId) {
          const downgraded = billing.applyPlanProvisioning(tenantId, "free_trial", {
            source: "kelviq_subscription_ended",
          });
          sendJson(res, 200, { ok: true, event_type: type, downgraded });
          return;
        }
        sendJson(res, 200, { ok: true, ignored: type });
      } catch (err) {
        sendJson(res, 400, {
          ok: false,
          error: { message: err instanceof Error ? err.message : "Kelviq webhook verification failed" },
        });
      }
      return;
    }

    // Resolve active tenant workspace for UI session calls
    const activeTenant = billing.resolveTenantFromRequest(req);

    if (req.method === "GET" && pathname === "/api/bootstrap") {
      await engine.init();
      sendJson(res, 200, {
        ok: true,
        product: {
          name: "REA Cloud Studio",
          tagline: "Enterprise Reverse-Engineering, Release Gate & RL Environment Factory",
          rea_version: "6.8.0",
          mcp_tools_available: engine.toolCount,
        },
        tenant: billing.sanitizeTenant(activeTenant),
        plans: Object.values(PLANS),
        billing_events: billing.state.billing_events.slice(0, 15),
        metrics: engine.metrics,
        samples: {
          electron: samples.electronTargets.map(({ path: _p, ...rest }) => rest),
          binary: samples.binaryTargets.map(({ path: _p, ...rest }) => rest),
          har: samples.harTargets.map(({ path: _p, ...rest }) => rest),
        },
        evidence_recent: engine.listEvidence().slice(0, 25),
        api_keys: billing.listTenantKeys(activeTenant.id),
      });
      return;
    }

    // -----------------------------------------------------------------------
    // Multi-Tenant Auth & Stripe Checkout Routes
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/auth/me") {
      sendJson(res, 200, {
        ok: true,
        tenant: billing.sanitizeTenant(activeTenant),
        plans: Object.values(PLANS),
        api_keys: billing.listTenantKeys(activeTenant.id),
        billing_events: billing.state.billing_events.filter((e) => e.tenant_id === activeTenant.id),
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/auth/register") {
      const body = await readJsonBody(req);
      const out = billing.register(body);
      sendJson(res, out.ok ? 200 : 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/auth/login") {
      const body = await readJsonBody(req);
      const out = billing.login(body);
      sendJson(res, out.ok ? 200 : 401, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/billing/checkout") {
      const body = await readJsonBody(req);
      const originUrl = resolvePublicOrigin(req);
      const out = await billing.createCheckoutSession(activeTenant, body.plan_id, originUrl);
      sendJson(res, out.ok ? 200 : 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/billing/confirm-sandbox") {
      const body = await readJsonBody(req);
      if (billing.stripeSecretKey || kelviq.isConfigured) {
        return sendJson(res, 403, {
          ok: false,
          error: { message: "Live billing keys are enabled; plans are provisioned via signed webhooks or license keys." },
        });
      }
      const out = billing.applyPlanProvisioning(activeTenant.id, body.plan_id, {
        source: "sandbox_checkout",
      });
      sendJson(res, out.ok ? 200 : 400, out);
      return;
    }

    // -----------------------------------------------------------------------
    // Kelviq Merchant-of-Record Routes + AlphaShield Deep EVM Audit
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/kelviq/status") {
      await kelviq.init();
      sendJson(res, 200, {
        ok: true,
        kelviq: kelviq.statusSummary(),
        tenant: billing.sanitizeTenant(activeTenant),
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/checkout") {
      const body = await readJsonBody(req);
      const originUrl = resolvePublicOrigin(req);
      const out = await kelviq.createCheckoutSession({
        tenant: activeTenant,
        planId: body.plan_id || "indie",
        chargePeriod: body.charge_period || "MONTHLY",
        originUrl,
      });
      sendJson(res, out.ok ? 200 : 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/portal") {
      const out = await kelviq.createPortalSession({ tenant: activeTenant });
      sendJson(res, out.ok ? 200 : 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/license/activate") {
      const body = await readJsonBody(req);
      const out = await kelviq.activateLicenseKey({
        licenseKey: body.license_key,
        tenant: activeTenant,
        instanceName: body.instance_name || "alphashield-web",
      });
      if (!out.ok) return sendJson(res, 400, out);
      const provisioned = billing.applyPlanProvisioning(activeTenant.id, out.plan_id, {
        source: "kelviq_license_key",
      });
      sendJson(res, 200, { ...out, tenant: provisioned.tenant });
      return;
    }

    if (req.method === "POST" && pathname === "/api/alphashield/evm-audit") {
      const body = await readJsonBody(req);
      const rawHex = String(body.bytecode || "").trim().replace(/^0x/i, "");
      if (!/^[0-9a-fA-F]{8,}$/.test(rawHex)) {
        return sendJson(res, 400, { ok: false, error: { message: "Provide valid hex contract bytecode." } });
      }
      const quota = billing.checkAndConsumeQuota(activeTenant, "scan");
      if (!quota.ok) return sendJson(res, quota.status || 402, quota);

      const carrier = join(engine.uploadsDir, `evm-${Date.now()}-${randomBytes(3).toString("hex")}.hex`);
      writeFileSync(carrier, rawHex);
      const inspected = await engine.inspectShipGateArtifact(carrier, "evm-bytecode");
      await kelviq.reportScanUsage(activeTenant.id, "contract-scans");
      sendJson(res, inspected.ok ? 200 : 422, { ...inspected, tenant: quota.tenant });
      return;
    }

    // -----------------------------------------------------------------------
    // File Upload Endpoint
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/upload") {
      const contentType = req.headers["content-type"] || "";
      let filename = sanitizeFilename(req.headers["x-filename"] || "uploaded.bin");
      let fileBuffer;

      if (contentType.includes("application/json")) {
        const body = await readJsonBody(req);
        filename = sanitizeFilename(body.filename || filename);
        fileBuffer = Buffer.from(String(body.base64 || ""), "base64");
      } else {
        fileBuffer = await readBodyBuffer(req);
      }

      const uploadSlot = join(engine.uploadsDir, `${Date.now()}-${randomBytes(4).toString("hex")}`);
      mkdirSync(uploadSlot, { recursive: true });
      const savedPath = join(uploadSlot, filename);
      writeFileSync(savedPath, fileBuffer);

      sendJson(res, 200, {
        ok: true,
        filename,
        bytes: fileBuffer.length,
        upload_id: basename(uploadSlot),
        saved_path: savedPath,
      });
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 1: Electron / JavaScript X-Ray Routes (Metered)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/xray/scan") {
      const body = await readJsonBody(req);
      let targetPath;
      let label;

      if (body.sample_id) {
        const found = samples.electronTargets.find((t) => t.id === body.sample_id);
        if (!found) return sendJson(res, 404, { ok: false, error: { message: "Unknown sample_id" } });
        targetPath = found.path;
        label = found.name;
      } else if (body.saved_path) {
        const candidate = resolve(body.saved_path);
        if (!candidate.startsWith(resolve(engine.uploadsDir))) {
          return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
        }
        if (candidate.toLowerCase().endsWith(".zip")) {
          const unpackedDir = join(dirname(candidate), "unpacked");
          extractZipSafely(candidate, unpackedDir);
          targetPath = unpackedDir;
        } else {
          targetPath = candidate;
        }
        label = basename(candidate);
      } else {
        return sendJson(res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
      }

      const quota = billing.checkAndConsumeQuota(activeTenant, "scan");
      if (!quota.ok) return sendJson(res, quota.status || 402, quota);

      const result = await engine.scanJavaScriptApplication(targetPath, label);
      sendJson(res, result.ok ? 200 : 422, { ...result, tenant: quota.tenant });
      return;
    }

    if (req.method === "POST" && pathname === "/api/xray/trace") {
      const body = await readJsonBody(req);
      const result = await engine.traceJavaScriptFeature(
        body.evidence_id,
        body.seed_kind || "channel",
        body.seed_value || "",
        body.direction || "both",
        body.match || "contains",
      );
      sendJson(res, result.ok ? 200 : 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/xray/compare") {
      const body = await readJsonBody(req);
      const resolveInput = (val, fallbackIdx) => {
        if (typeof val === "string" && val.startsWith("ev_")) return val;
        const found = samples.electronTargets.find((t) => t.id === val) ?? samples.electronTargets[fallbackIdx];
        return found.path;
      };
      const left = resolveInput(body.left || "acme-desktop-v1", 0);
      const right = resolveInput(body.right || "acme-desktop-v2", 1);
      const result = await engine.compareJavaScriptVersions(left, right);
      sendJson(res, result.ok ? 200 : 422, result);
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 2: ShipGate Binary / Model / EVM / Bytecode Gate Routes (Metered)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/shipgate/inspect") {
      const body = await readJsonBody(req);
      let targetPath;
      let category = body.category || "auto";

      if (body.sample_id) {
        const found = samples.binaryTargets.find((t) => t.id === body.sample_id);
        if (!found) return sendJson(res, 404, { ok: false, error: { message: "Unknown binary sample_id" } });
        targetPath = found.path;
        if (category === "auto") category = found.category;
      } else if (body.saved_path) {
        const candidate = resolve(body.saved_path);
        if (!candidate.startsWith(resolve(engine.uploadsDir))) {
          return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
        }
        targetPath = candidate;
      } else {
        return sendJson(res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
      }

      const quota = billing.checkAndConsumeQuota(activeTenant, "scan");
      if (!quota.ok) return sendJson(res, quota.status || 402, quota);

      const result = await engine.inspectShipGateArtifact(targetPath, category, {
        symbol: body.symbol || undefined,
      });
      sendJson(res, result.ok ? 200 : 422, { ...result, tenant: quota.tenant });
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 3: HAR-to-RL AgentEnv Factory Routes (Metered)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/rl/build") {
      const body = await readJsonBody(req);
      let harPath;
      let envName = body.name || "agent-env";

      if (body.sample_id) {
        const found = samples.harTargets.find((t) => t.id === body.sample_id);
        if (!found) return sendJson(res, 404, { ok: false, error: { message: "Unknown HAR sample_id" } });
        harPath = found.path;
        envName = body.name || found.envName;
      } else if (body.saved_path) {
        const candidate = resolve(body.saved_path);
        if (!candidate.startsWith(resolve(engine.uploadsDir))) {
          return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
        }
        harPath = candidate;
        envName = body.name || basename(candidate, extname(candidate));
      } else {
        return sendJson(res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
      }

      const quota = billing.checkAndConsumeQuota(activeTenant, "rl_build");
      if (!quota.ok) return sendJson(res, quota.status || 402, quota);

      const result = await engine.buildAndServeAgentEnvironment(harPath, envName);
      sendJson(res, result.ok ? 200 : 422, { ...result, tenant: quota.tenant });
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/call") {
      const body = await readJsonBody(req);
      const result = await engine.callLiveAgentTool(body.env_id, body.tool, body.arguments || {});
      sendJson(res, result.ok ? 200 : 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/reset") {
      const body = await readJsonBody(req);
      const result = await engine.resetLiveAgentState(body.env_id);
      sendJson(res, result.ok ? 200 : 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/grade-task") {
      const body = await readJsonBody(req);
      const result = await engine.evaluateAndSaveRlTask(body.env_id, body.task || {});
      sendJson(res, result.ok ? 200 : 422, result);
      return;
    }

    if (req.method === "GET" && pathname.startsWith("/api/rl/download/")) {
      const envId = decodeURIComponent(pathname.slice("/api/rl/download/".length));
      const env = engine.liveEnvironments.get(envId);
      if (!env) return sendJson(res, 404, { ok: false, error: { message: "Environment bundle not found" } });

      const zipBuf = zipDirectory(env.bundle_dir, env.name);
      res.writeHead(200, {
        "content-type": "application/zip",
        "content-length": zipBuf.length,
        "content-disposition": `attachment; filename="${env.name}-agentenv.zip"`,
        "cache-control": "no-store",
      });
      res.end(zipBuf);
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 4: Evidence Ledger, Per-Tenant API Keys & Commercial B2B API v1
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/evidence") {
      sendJson(res, 200, {
        ok: true,
        tenant: billing.sanitizeTenant(activeTenant),
        metrics: engine.metrics,
        records: engine.listEvidence(),
      });
      return;
    }

    const reportMatch = pathname.match(/^\/api\/evidence\/(ev_[a-f0-9]{64})\/report$/);
    if (req.method === "GET" && reportMatch) {
      const record = engine.getEvidenceRecord(reportMatch[1]);
      if (!record) return sendJson(res, 404, { ok: false, error: { message: "Evidence not found" } });
      const format = url.searchParams.get("format") || "md";
      if (format === "json") {
        const jsonBytes = Buffer.from(JSON.stringify(record.evidence, null, 2), "utf8");
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "content-length": jsonBytes.length,
          "content-disposition": `attachment; filename="${record.evidence_id.slice(0, 16)}.evidence.json"`,
        });
        res.end(jsonBytes);
      } else {
        const md = renderAuditMarkdown(record, record.posture ?? null);
        const mdBytes = Buffer.from(md, "utf8");
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "content-length": mdBytes.length,
          "content-disposition": `attachment; filename="${record.evidence_id.slice(0, 16)}-audit.md"`,
        });
        res.end(mdBytes);
      }
      return;
    }

    const detailMatch = pathname.match(/^\/api\/evidence\/(ev_[a-f0-9]{64})$/);
    if (req.method === "GET" && detailMatch) {
      const record = engine.getEvidenceRecord(detailMatch[1]);
      if (!record) return sendJson(res, 404, { ok: false, error: { message: "Evidence not found" } });
      sendJson(res, 200, { ok: true, record });
      return;
    }

    if (req.method === "POST" && pathname === "/api/keys/create") {
      const body = await readJsonBody(req);
      const out = billing.createApiKey(activeTenant.id, body.name);
      sendJson(res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/keys/revoke") {
      const body = await readJsonBody(req);
      const out = billing.revokeApiKey(activeTenant.id, body.key_id);
      sendJson(res, out.ok ? 200 : 404, out);
      return;
    }

    // Authenticated & Quota-Metered B2B SaaS REST API v1
    if (pathname.startsWith("/api/v1/")) {
      const authCtx = billing.authenticateApiKey(req);
      if (!authCtx) {
        return sendJson(res, 401, {
          ok: false,
          error: {
            code: "unauthorized",
            message: "Missing or invalid Bearer API key. Generate a key in the Monetization & API Console tab.",
          },
        });
      }
      engine.metrics.api_requests += 1;
      const { keyRec, tenant } = authCtx;

      if (req.method === "GET" && pathname === "/api/v1/status") {
        return sendJson(res, 200, {
          ok: true,
          authenticated_as: keyRec.name,
          organization: tenant.org_name,
          tenant: billing.sanitizeTenant(tenant),
          key_calls: keyRec.calls,
          rea_mcp_tools: engine.toolCount,
          metrics: engine.metrics,
        });
      }

      if (req.method === "POST" && pathname === "/api/v1/upload") {
        const contentType = req.headers["content-type"] || "";
        let filename = sanitizeFilename(req.headers["x-filename"] || "uploaded.bin");
        let fileBuffer;
        if (contentType.includes("application/json")) {
          const body = await readJsonBody(req);
          filename = sanitizeFilename(body.filename || filename);
          fileBuffer = Buffer.from(String(body.base64 || ""), "base64");
        } else {
          fileBuffer = await readBodyBuffer(req);
        }
        const uploadSlot = join(engine.uploadsDir, `${Date.now()}-${randomBytes(4).toString("hex")}`);
        mkdirSync(uploadSlot, { recursive: true });
        const savedPath = join(uploadSlot, filename);
        writeFileSync(savedPath, fileBuffer);
        return sendJson(res, 200, {
          ok: true,
          filename,
          bytes: fileBuffer.length,
          upload_id: basename(uploadSlot),
          saved_path: savedPath,
          billed_to: tenant.org_name,
        });
      }

      if (req.method === "POST" && pathname === "/api/v1/xray") {
        const body = await readJsonBody(req);
        let targetPath;
        let label;
        if (body.saved_path) {
          const candidate = resolve(body.saved_path);
          if (!candidate.startsWith(resolve(engine.uploadsDir))) {
            return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
          }
          if (candidate.toLowerCase().endsWith(".zip")) {
            const unpackedDir = join(dirname(candidate), "unpacked");
            extractZipSafely(candidate, unpackedDir);
            targetPath = unpackedDir;
          } else {
            targetPath = candidate;
          }
          label = body.label || basename(candidate);
        } else {
          const sample = samples.electronTargets.find((t) => t.id === (body.target || "acme-desktop-v1"));
          if (!sample) return sendJson(res, 404, { ok: false, error: { message: "Unknown target" } });
          targetPath = sample.path;
          label = sample.name;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "scan");
        if (!quota.ok) return sendJson(res, quota.status || 402, quota);

        const result = await engine.scanJavaScriptApplication(targetPath, label);
        const rec = result.ok ? engine.getEvidenceRecord(result.evidence_id) : null;
        return sendJson(res, result.ok ? 200 : 422, {
          ...result,
          ...(body.include_markdown && rec ? { audit_markdown: renderAuditMarkdown(rec, rec.posture ?? null) } : {}),
          billed_to: tenant.org_name,
          tenant: quota.tenant,
        });
      }

      if (req.method === "POST" && pathname === "/api/v1/shipgate") {
        const body = await readJsonBody(req);
        let targetPath;
        let category = body.category || "auto";
        if (body.saved_path) {
          const candidate = resolve(body.saved_path);
          if (!candidate.startsWith(resolve(engine.uploadsDir))) {
            return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
          }
          targetPath = candidate;
        } else {
          const sample = samples.binaryTargets.find((t) => t.id === (body.target || "libvault-elf"));
          if (!sample) return sendJson(res, 404, { ok: false, error: { message: "Unknown target" } });
          targetPath = sample.path;
          if (category === "auto") category = sample.category;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "scan");
        if (!quota.ok) return sendJson(res, quota.status || 402, quota);

        const result = await engine.inspectShipGateArtifact(targetPath, category, {
          symbol: body.symbol || undefined,
        });
        return sendJson(res, result.ok ? 200 : 422, {
          ...result,
          billed_to: tenant.org_name,
          tenant: quota.tenant,
        });
      }

      if (req.method === "POST" && pathname === "/api/v1/rl/build") {
        const body = await readJsonBody(req);
        let harPath;
        let envName = body.name || "agent-env";
        if (body.saved_path) {
          const candidate = resolve(body.saved_path);
          if (!candidate.startsWith(resolve(engine.uploadsDir))) {
            return sendJson(res, 400, { ok: false, error: { message: "Upload path out of scope" } });
          }
          harPath = candidate;
          envName = body.name || basename(candidate, extname(candidate));
        } else {
          const sample = samples.harTargets.find((t) => t.id === (body.target || "helpdesk-crm"));
          if (!sample) return sendJson(res, 404, { ok: false, error: { message: "Unknown HAR target" } });
          harPath = sample.path;
          envName = body.name || sample.envName;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "rl_build");
        if (!quota.ok) return sendJson(res, quota.status || 402, quota);

        const result = await engine.buildAndServeAgentEnvironment(harPath, envName);
        return sendJson(res, result.ok ? 200 : 422, {
          ...result,
          download_path: result.ok ? `/api/rl/download/${encodeURIComponent(result.env_id)}` : null,
          billed_to: tenant.org_name,
          tenant: quota.tenant,
        });
      }

      return sendJson(res, 404, { ok: false, error: { message: "Unknown v1 endpoint" } });
    }

    // -----------------------------------------------------------------------
    // Static Frontend Serving (/alphashield + Studio SPA)
    // -----------------------------------------------------------------------
    if (pathname === "/alphashield" || pathname === "/alphashield/") {
      const alphaHtml = readFileSync(join(ALPHASHIELD_DIR, "index.html"));
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-length": alphaHtml.length,
        "cache-control": "no-cache",
      });
      res.end(alphaHtml);
      return;
    }

    if (pathname === "/solidcraft" || pathname === "/solidcraft/") {
      const scHtml = readFileSync(join(STUDIO_ROOT, "solidcraft", "index.html"));
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-length": scHtml.length,
        "cache-control": "no-cache",
      });
      res.end(scHtml);
      return;
    }

    let filePath = pathname === "/" ? join(PUBLIC_DIR, "index.html") : join(PUBLIC_DIR, normalize(pathname));
    if (!filePath.startsWith(PUBLIC_DIR) || !existsSync(filePath)) {
      filePath = join(PUBLIC_DIR, "index.html");
    }
    const ext = extname(filePath).toLowerCase();
    const content = readFileSync(filePath);
    res.writeHead(200, {
      "content-type": MIME_TYPES[ext] || "application/octet-stream",
      "content-length": content.length,
      "cache-control": "no-cache",
    });
    res.end(content);
  } catch (err) {
    sendJson(res, 500, {
      ok: false,
      error: {
        message: err instanceof Error ? err.message : String(err),
      },
    });
  }
});

await engine.init();

server.listen(PORT, HOST, () => {
  console.log(
    `REA Cloud Studio listening on http://${HOST}:${PORT} (REA v6.8.0 · ${engine.toolCount} MCP tools ready)`,
  );
});

const shutdown = async () => {
  server.close();
  await engine.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
