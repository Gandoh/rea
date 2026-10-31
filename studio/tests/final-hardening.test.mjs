import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { promisify } from "node:util";
import { deflateRawSync } from "node:zlib";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { ReaStudioEngine } from "../server/reaEngine.mjs";
import { TenantBillingStore } from "../server/tenantBilling.mjs";
import {
  backupSqliteDatabase,
  restoreSqliteDatabase,
  verifySqliteBackup,
} from "../scripts/sqliteBackup.mjs";

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(import.meta.dirname, "../..");

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildValidMultiFileZip(files) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const { name, content } of files) {
    const nameBuf = Buffer.from(name, "utf8");
    const rawBuf = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
    const compBuf = deflateRawSync(rawBuf, { level: 6 });
    const crc = crc32(rawBuf);

    const lfh = Buffer.alloc(30 + nameBuf.length);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(8, 8);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(compBuf.length, 18);
    lfh.writeUInt32LE(rawBuf.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(lfh, 30);

    const cdh = Buffer.alloc(46 + nameBuf.length);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE((3 << 8) | 20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(8, 10);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(compBuf.length, 20);
    cdh.writeUInt32LE(rawBuf.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt32LE(offset, 42);
    nameBuf.copy(cdh, 46);

    localParts.push(lfh, compBuf);
    cdParts.push(cdh);
    offset += lfh.length + compBuf.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

async function startMockChainRpc({ chainIdHex, tokenAddress, merchantWallet }) {
  const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const txMap = new Map();
  let currentChainId = chainIdHex;

  const setTransfer = ({
    txHash,
    fromWallet,
    toWallet = merchantWallet,
    rawUnits,
    confirmations = 20,
    reorged = false,
  }) => {
    const clean = txHash.toLowerCase();
    const blkNum = 1000 + txMap.size;
    const blkHex = `0x${blkNum.toString(16)}`;
    const receiptBlkHash = `0x${blkNum.toString(16).padStart(64, "b")}`;
    const canonicalBlkHash = reorged
      ? `0x${blkNum.toString(16).padStart(64, "c")}`
      : receiptBlkHash;
    const paddedFrom = `0x${fromWallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
    const paddedTo = `0x${toWallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
    const dataHex = `0x${BigInt(rawUnits).toString(16).padStart(64, "0")}`;

    txMap.set(clean, {
      blkNum,
      blkHex,
      confirmations,
      canonicalBlkHash,
      receipt: {
        status: "0x1",
        blockNumber: blkHex,
        blockHash: receiptBlkHash,
        logs: [
          {
            address: tokenAddress.toLowerCase(),
            topics: [TRANSFER_TOPIC, paddedFrom, paddedTo],
            data: dataHex,
          },
        ],
      },
    });
  };

  const srv = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const reply = (result) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      };

      if (body.method === "eth_chainId") return reply(currentChainId);
      if (body.method === "eth_getTransactionReceipt") {
        return reply(txMap.get(String(body.params?.[0] || "").toLowerCase())?.receipt || null);
      }
      if (body.method === "eth_blockNumber") {
        let head = 1020;
        for (const rec of txMap.values()) {
          head = rec.blkNum + Number(rec.confirmations);
        }
        return reply(`0x${Math.max(0, head).toString(16)}`);
      }
      if (body.method === "eth_getBlockByNumber") {
        const blk = body.params?.[0];
        let hash = `0x${String(blk || "0x0").replace(/^0x/, "").padStart(64, "b")}`;
        for (const rec of txMap.values()) {
          if (rec.blkHex === blk) {
            hash = rec.canonicalBlkHash;
            break;
          }
        }
        const ts = Math.floor(Date.now() / 1000) - 12;
        return reply({ number: blk, hash, timestamp: `0x${ts.toString(16)}` });
      }
      return reply(null);
    });
  });

  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${srv.address().port}`,
    setTransfer,
    setChainId: (hex) => {
      currentChainId = hex;
    },
    close: () => new Promise((r) => srv.close(r)),
  };
}

async function startMockKelviq() {
  const licenses = new Map();
  let activateCalls = 0;
  let portalCalls = 0;

  const srv = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw ? JSON.parse(raw) : {};
      const send = (status, obj) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(obj));
      };

      if (req.url?.includes("/license/validate")) {
        const key = body.license_key || body.licenseKey;
        const rec = licenses.get(key);
        if (!rec) return send(200, { valid: false, detail: "Invalid license key" });
        return send(200, { valid: true, license: rec });
      }
      if (req.url?.includes("/license/activate")) {
        activateCalls += 1;
        const key = body.license_key || body.licenseKey;
        const rec = licenses.get(key);
        if (!rec) return send(400, { detail: "Invalid license key" });
        setTimeout(() => {
          send(200, {
            activated: true,
            instanceId: `inst_${activateCalls}`,
            expiresOn: rec.expiresOn,
            license: rec,
          });
        }, 40);
        return;
      }
      if (req.url?.includes("/portal")) {
        portalCalls += 1;
        return send(200, {
          portalUrl: "https://portal.kelviq.test/session/ok",
          url: "https://portal.kelviq.test/session/ok",
        });
      }
      if (req.url?.includes("/customers")) {
        return send(200, { id: body.customer_id || body.customerId || "cus_ok" });
      }
      if (req.url?.includes("/checkout")) {
        return send(200, {
          checkoutSessionId: "kvq_cs_1",
          checkoutUrl: "https://pay.kelviq.test/session/1",
        });
      }
      return send(200, { ok: true });
    });
  });

  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${srv.address().port}`,
    licenses,
    getActivateCalls: () => activateCalls,
    getPortalCalls: () => portalCalls,
    close: () => new Promise((r) => srv.close(r)),
  };
}

function isEphemeralTmpLocation(candidatePath) {
  const resolved = resolve(candidatePath);
  let real = resolved;
  try {
    real = realpathSync(resolved);
  } catch {
    try {
      real = join(realpathSync(dirname(resolved)), resolved.slice(dirname(resolved).length));
    } catch {
      real = resolved;
    }
  }
  const sysTmp = resolve(tmpdir());
  let sysTmpReal = sysTmp;
  try {
    sysTmpReal = realpathSync(sysTmp);
  } catch {
    sysTmpReal = sysTmp;
  }
  for (const p of [resolved, real]) {
    for (const prefix of ["/tmp", "/var/tmp", "/private/tmp", sysTmp, sysTmpReal]) {
      if (p === prefix || p.startsWith(`${prefix}/`)) return true;
    }
  }
  return false;
}

function createDurableTestDataRoot(preferredParent) {
  const candidates = [
    preferredParent,
    process.env.XDG_STATE_HOME ? join(process.env.XDG_STATE_HOME, "rea-studio-tests") : null,
    process.env.XDG_CACHE_HOME ? join(process.env.XDG_CACHE_HOME, "rea-studio-tests") : null,
    homedir() ? join(homedir(), ".cache", "rea-studio-tests") : null,
    "/dev/shm/rea-studio-tests",
  ].filter(Boolean);

  for (const base of candidates) {
    if (isEphemeralTmpLocation(base)) continue;
    try {
      mkdirSync(base, { recursive: true, mode: 0o700 });
      if (isEphemeralTmpLocation(base)) continue;
      return mkdtempSync(join(base, ".test-data-"));
    } catch {
      // try next non-/tmp writable parent
    }
  }
  throw new Error("Unable to allocate a non-/tmp directory for production-mode test data.");
}

async function startServerInstance(envOverrides = {}, options = {}) {
  const effectiveRepoRoot = options.cwdOverride ? resolve(options.cwdOverride) : REPO_ROOT;
  const rootTmp = mkdtempSync(join(tmpdir(), "rea-final-rt-"));
  const persistentRoot = createDurableTestDataRoot(join(effectiveRepoRoot, "studio"));
  const runtimeDir = join(rootTmp, "runtime");
  const dataDir = envOverrides.REA_STUDIO_DATA_DIR || join(persistentRoot, "data");

  const probe = createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));

  const proc = spawn("node", ["studio/server/index.mjs"], {
    cwd: effectiveRepoRoot,
    env: {
      ...process.env,
      PORT: String(port),
      REA_STUDIO_RUNTIME_DIR: runtimeDir,
      REA_STUDIO_DATA_DIR: dataDir,
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let logs = "";
  proc.stdout.on("data", (d) => {
    logs += d.toString();
  });
  proc.stderr.on("data", (d) => {
    logs += d.toString();
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 60; i += 1) {
    if (proc.exitCode !== null) break;
    try {
      const r = await fetch(`${baseUrl}/api/health`);
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {
      // wait
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  if (!ready) {
    proc.kill("SIGKILL");
    rmSync(rootTmp, { recursive: true, force: true });
    rmSync(persistentRoot, { recursive: true, force: true });
    throw new Error(`Server failed to start:\n${logs}`);
  }

  return {
    baseUrl,
    runtimeDir,
    dataDir,
    stop: async () => {
      proc.kill("SIGTERM");
      await new Promise((r) => proc.once("exit", r));
      rmSync(rootTmp, { recursive: true, force: true });
      rmSync(persistentRoot, { recursive: true, force: true });
    },
  };
}

function createBrowserAgent(baseUrl, defaultOrigin = baseUrl) {
  let cookie = "";
  let csrf = "";
  let apiKey = "";
  let tenant = null;

  return {
    getCookie: () => cookie,
    getCsrf: () => csrf,
    getApiKey: () => apiKey,
    getTenant: () => tenant,
    async request(path, opts = {}) {
      const method = String(opts.method || "GET").toUpperCase();
      const headers = {
        ...(defaultOrigin ? { origin: defaultOrigin } : {}),
        ...(cookie ? { cookie } : {}),
        ...(method !== "GET" && method !== "HEAD" && !opts.skipCsrf && csrf
          ? { "x-csrf-token": csrf }
          : {}),
        ...(opts.headers || {}),
      };
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: opts.body,
      });
      const sc = res.headers.get("set-cookie");
      if (sc) {
        const pair = sc.split(";")[0];
        cookie = pair.endsWith("=") ? "" : pair;
      }
      const ct = res.headers.get("content-type") || "";
      const body = ct.includes("application/json") ? await res.json() : await res.text();
      if (body && typeof body === "object") {
        if (body.csrf_token) csrf = body.csrf_token;
        if (body.tenant) tenant = body.tenant;
        if (body.starter_api_key?.secret_token) apiKey = body.starter_api_key.secret_token;
      }
      return { status: res.status, headers: res.headers, body };
    },
  };
}

function rawWireRequest(baseUrl, path, { method = "POST", headers = {}, bodyObj = null } = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const u = new URL(path, baseUrl);
    const payload = bodyObj !== null ? JSON.stringify(bodyObj) : "";
    const req = httpRequest(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers: {
          ...(bodyObj !== null
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(payload),
              }
            : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed = text;
          try {
            parsed = JSON.parse(text);
          } catch {
            // plain text
          }
          resolvePromise({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      },
    );
    req.on("error", rejectPromise);
    if (bodyObj !== null) req.write(payload);
    req.end();
  });
}

test("Final Security Hardening Suite — F-01 through F-12 Complete Verification", async (t) => {
  const MERCHANT = "0x9999999999999999999999999999999999999999";
  const BSC_USDT = "0x55d398326f99059ff775485246999027b3197955";
  const ETH_USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7";

  const mockKelviq = await startMockKelviq();
  const mockBsc = await startMockChainRpc({
    chainIdHex: "0x38",
    tokenAddress: BSC_USDT,
    merchantWallet: MERCHANT,
  });
  const mockEth = await startMockChainRpc({
    chainIdHex: "0x1",
    tokenAddress: ETH_USDT,
    merchantWallet: MERCHANT,
  });

  t.after(async () => {
    await mockKelviq.close();
    await mockBsc.close();
    await mockEth.close();
  });

  // =========================================================================
  // 1. F-03: Strict Bearer API Key vs Browser Session Auth + Portal Limiter + License Mutex
  // =========================================================================
  await t.test("F-03: Blocks Bearer API keys from all billing/portal/license/browser routes while preserving /api/v1/* and session workflows", async () => {
    const srv = await startServerInstance({
      KELVIQ_SERVER_API_KEY: "kvq_test_secret_1",
      KELVIQ_CLIENT_API_KEY: "kvq_client_test_1",
      KELVIQ_API_BASE_URL: mockKelviq.url,
      ALPHASHIELD_ENABLE_DIRECT_USDT: "true",
      ALPHASHIELD_MERCHANT_WALLET: MERCHANT,
      ALPHASHIELD_RPC_URL_BSC: mockBsc.url,
      ALPHASHIELD_RPC_URL_ETHEREUM: mockEth.url,
    });
    try {
      const browserA = createBrowserAgent(srv.baseUrl);
      const regA = await browserA.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "Alpha Corp",
          email: "sec-a@alphacorp.test",
          password: "strong-password-1234",
        }),
      });
      assert.equal(regA.status, 200);
      const apiKey = browserA.getApiKey();
      assert.ok(apiKey.startsWith("rea_sk_live_"));

      // Bearer key MUST be rejected with 403 api_key_forbidden across every browser/billing/payment/key endpoint
      const browserOnlyEndpoints = [
        ["GET", "/api/auth/me", null],
        ["POST", "/api/kelviq/portal", {}],
        ["POST", "/api/kelviq/checkout", { plan_id: "alphashield_pro" }],
        ["POST", "/api/kelviq/license/activate", { license_key: "KVQ-TEST" }],
        ["POST", "/api/billing/checkout", { plan_id: "indie" }],
        ["POST", "/api/billing/confirm-sandbox", { plan_id: "indie" }],
        [
          "POST",
          "/api/alphashield/payment-intent",
          { chain: "bsc", plan_id: "alphashield_pro", payer_wallet: "0x1111111111111111111111111111111111111111" },
        ],
        ["POST", "/api/alphashield/verify-tx", { intent_id: "pi_1", tx_hash: `0x${"a".repeat(64)}` }],
        ["POST", "/api/alphashield/evm-audit", { bytecode: "6080604052" }],
        ["POST", "/api/alphashield/apk-audit", { filename: "a.apk", sample_base64: Buffer.from("PK\x03\x04").toString("base64") }],
        ["POST", "/api/keys/create", { name: "Escalated Key" }],
        ["POST", "/api/keys/revoke", { key_id: "key_1" }],
        ["GET", "/api/evidence", null],
        ["POST", "/api/xray/scan", { sample_id: "acme-desktop-v1" }],
        ["POST", "/api/shipgate/inspect", { sample_id: "libvault-elf" }],
        ["POST", "/api/rl/build", { sample_id: "helpdesk-crm" }],
      ];

      for (const [method, path, payload] of browserOnlyEndpoints) {
        const res = await fetch(`${srv.baseUrl}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${apiKey}`,
            ...(payload ? { "content-type": "application/json" } : {}),
          },
          body: payload ? JSON.stringify(payload) : undefined,
        });
        const json = await res.json();
        assert.equal(res.status, 403, `Expected 403 for Bearer key on ${method} ${path}, got ${res.status}`);
        assert.equal(json.error?.code, "api_key_forbidden");
      }

      // Meanwhile, headless /api/v1/* endpoints MUST succeed with the exact same Bearer API key
      const v1Status = await fetch(`${srv.baseUrl}/api/v1/status`, {
        headers: { authorization: `Bearer ${apiKey}` },
      });
      assert.equal(v1Status.status, 200);

      const v1Scan = await fetch(`${srv.baseUrl}/api/v1/xray`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ target: "acme-desktop-v1" }),
      });
      assert.equal(v1Scan.status, 200);

      // Authenticated browser session WITH CSRF + Origin succeeds on portal & checkout, and enforces authPairLimiter on portal
      const portalOk = await browserA.request("/api/kelviq/portal", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      assert.equal(portalOk.status, 200);

      // Missing CSRF on browser session fails with 403
      const portalNoCsrf = await browserA.request("/api/kelviq/portal", {
        method: "POST",
        skipCsrf: true,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      assert.equal(portalNoCsrf.status, 403);

      // Rapid portal calls hit authPairLimiter (429)
      let hitPortal429 = false;
      for (let i = 0; i < 15; i += 1) {
        const r = await browserA.request("/api/kelviq/portal", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({}),
        });
        if (r.status === 429) {
          hitPortal429 = true;
          break;
        }
      }
      assert.equal(hitPortal429, true, "POST /api/kelviq/portal must enforce rate limiting (429)");

      // Concurrent license activation race: two tenants activating the same key simultaneously
      const browserB = createBrowserAgent(srv.baseUrl);
      await browserB.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "Beta Corp",
          email: "sec-b@betacorp.test",
          password: "strong-password-1234",
        }),
      });
      const sharedKey = "KVQ-RACE-SINGLE-SEAT";
      mockKelviq.licenses.set(sharedKey, {
        status: "ACTIVE",
        planIdentifier: "alphashield-pro",
        expiresOn: new Date(Date.now() + 86_400_000 * 30).toISOString(),
      });
      const beforeUpstreamCalls = mockKelviq.getActivateCalls();
      const [licResA, licResB] = await Promise.all([
        browserA.request("/api/kelviq/license/activate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ license_key: sharedKey }),
        }),
        browserB.request("/api/kelviq/license/activate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ license_key: sharedKey }),
        }),
      ]);
      const statuses = [licResA.status, licResB.status].sort((a, b) => a - b);
      assert.deepEqual(statuses, [200, 409], "Exactly one tenant must bind the license; concurrent rival must get 409");
      assert.equal(
        mockKelviq.getActivateCalls() - beforeUpstreamCalls,
        1,
        "withLicenseMutex must prevent upstream seat activation for the rejected second tenant",
      );
    } finally {
      await srv.stop();
    }
  });

  // =========================================================================
  // 2. F-01 & F-02: Docker/Render Manifests, Production /tmp Refusal & SQLite Backup/Restore
  // =========================================================================
  await t.test("F-01 & F-02: Validates Dockerfile/.dockerignore/render.yaml, blocks ephemeral /tmp DATA_DIR in production, and round-trips SQLite VACUUM INTO backup/restore", async () => {
    const dockerignore = readFileSync(join(REPO_ROOT, ".dockerignore"), "utf8");
    for (const expectedPattern of [".git", "node_modules", ".env", "studio/data", "*.sqlite", "skills", "studio/solidcraft"]) {
      assert.ok(dockerignore.includes(expectedPattern), `.dockerignore missing ${expectedPattern}`);
    }

    const dockerfile = readFileSync(join(REPO_ROOT, "studio/Dockerfile"), "utf8");
    assert.equal(dockerfile.includes("COPY skills"), false, "Dockerfile must NOT copy gitignored skills/");
    assert.ok(dockerfile.includes("turbo.json"), "Dockerfile must include turbo.json for build:cached");
    assert.ok(dockerfile.includes(".agents/skills/reverse-engineer-anything"), "Dockerfile must copy .agents skill source");
    assert.ok(dockerfile.includes("COPY bridge ./bridge"), "Dockerfile must copy bridge/ runtime helpers");
    assert.ok(dockerfile.includes("npm ci"), "Dockerfile must use deterministic npm ci");
    assert.ok(dockerfile.includes("node:24.22.1-bookworm-slim"), "Dockerfile must align with .nvmrc 24.22.1");

    const renderYaml = readFileSync(join(REPO_ROOT, "studio/render.yaml"), "utf8");
    assert.ok(renderYaml.includes("mountPath: /data"), "render.yaml must mount persistent disk at /data");
    assert.ok(renderYaml.includes("REA_STUDIO_DATA_DIR"), "render.yaml must configure REA_STUDIO_DATA_DIR");
    assert.ok(renderYaml.includes("PUBLIC_BASE_URL"), "render.yaml must declare PUBLIC_BASE_URL");
    assert.ok(renderYaml.includes("TRUSTED_PROXY_IPS"), "render.yaml must declare TRUSTED_PROXY_IPS");

    // Production startup MUST fail closed when REA_STUDIO_DATA_DIR resolves inside /tmp
    const ephemeralTmpDir = mkdtempSync(join(tmpdir(), "rea-ephemeral-prod-"));
    try {
      let failedAsExpected = false;
      try {
        await execFileAsync("node", ["studio/server/index.mjs"], {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            NODE_ENV: "production",
            REA_STUDIO_DATA_DIR: join(ephemeralTmpDir, "data"),
            REA_STUDIO_NO_AUTO_LISTEN: "true",
          },
        });
      } catch (err) {
        failedAsExpected = true;
        assert.match(String(err.stderr || err.message), /ephemeral \/tmp storage/i);
      }
      assert.equal(failedAsExpected, true, "Production startup must refuse /tmp REA_STUDIO_DATA_DIR");
      assert.equal(
        existsSync(join(ephemeralTmpDir, "data", "studio.sqlite")),
        false,
        "Must abort before creating SQLite DB in /tmp",
      );
    } finally {
      rmSync(ephemeralTmpDir, { recursive: true, force: true });
    }

    // Online SQLite backup, integrity verification & atomic restore round-trip
    const workRoot = createDurableTestDataRoot(join(REPO_ROOT, "studio"));
    try {
      const liveDbPath = join(workRoot, "live", "studio.sqlite");
      const backupPath = join(workRoot, "backups", "snapshot.sqlite");
      const restoredDbPath = join(workRoot, "restored", "studio.sqlite");

      const store = new TenantBillingStore(join(workRoot, "live", "legacy.json"), {
        sqlitePath: liveDbPath,
      });
      const reg = store.register({
        org_name: "Durable Vault LLC",
        email: "ops@durable.test",
        password: "durable-password-1234",
      });
      assert.equal(reg.ok, true);
      const intentRes = store.createUsdtPaymentIntent({
        tenantId: reg.tenant.id,
        chain: "bsc",
        payerWallet: "0x2222222222222222222222222222222222222222",
        planId: "alphashield_pro",
        chargePeriod: "MONTHLY",
        baseUsd: 19,
        decimals: 18,
      });
      const redeemedTx = `0x${"7".repeat(64)}`;
      const red = store.redeemUsdtPaymentIntent({
        intentId: intentRes.intent.intent_id,
        tenantId: reg.tenant.id,
        chain: "bsc",
        txHash: redeemedTx,
        matchedSymbol: "USDT",
      });
      assert.equal(red.ok, true);
      store.markWebhookProcessed("kelviq", "evt_replay_guard_001");

      // Run online VACUUM INTO backup WHILE store WAL connection is still open!
      const bkReport = backupSqliteDatabase(liveDbPath, backupPath);
      assert.equal(bkReport.ok, true);
      assert.equal(bkReport.integrity, "ok");
      assert.equal(statSync(backupPath).mode & 0o777, 0o600);
      assert.equal(bkReport.counts.consumed_tx_hashes, 1);
      assert.equal(bkReport.counts.processed_webhook_ids, 1);

      store.close();

      // Verify CLI `verify` command works
      const cliVerify = await execFileAsync("node", ["studio/scripts/sqliteBackup.mjs", "verify", backupPath], {
        cwd: REPO_ROOT,
      });
      assert.equal(JSON.parse(cliVerify.stdout).ok, true);

      // Restore atomically into a fresh target path and verify replay tables & entitlements survive
      const restoreReport = restoreSqliteDatabase(backupPath, restoredDbPath);
      assert.equal(restoreReport.ok, true);
      assert.equal(statSync(restoredDbPath).mode & 0o777, 0o600);

      const restoredStore = new TenantBillingStore(join(workRoot, "restored", "legacy.json"), {
        sqlitePath: restoredDbPath,
      });
      try {
        assert.equal(restoredStore.isTxHashConsumed("bsc", redeemedTx), true, "Redeemed USDT tx replay table preserved");
        assert.equal(restoredStore.isWebhookProcessed("kelviq", "evt_replay_guard_001"), true, "Webhook replay table preserved");
        const loginAfterRestore = restoredStore.login({
          email: "ops@durable.test",
          password: "durable-password-1234",
        });
        assert.equal(loginAfterRestore.ok, true);
        assert.equal(loginAfterRestore.tenant.alphashield_plan_id, "alphashield_pro");
      } finally {
        restoredStore.close();
      }
    } finally {
      rmSync(workRoot, { recursive: true, force: true });
    }
  });

  // =========================================================================
  // 3. F-07 & F-08: Origin/Host Fallback Removal, Chain Finality Depth & Server AlphaShield Paywall
  // =========================================================================
  await t.test("F-07 & F-08: Blocks Host-header Origin fallback, enforces >=15 BSC / >=12 ETH confirmations, and enforces server-side AlphaShield free-tier quota", async () => {
    const srv = await startServerInstance({
      PUBLIC_BASE_URL: "https://studio.rea.security",
      ALPHASHIELD_ENABLE_DIRECT_USDT: "true",
      ALPHASHIELD_MERCHANT_WALLET: MERCHANT,
      ALPHASHIELD_RPC_URL_BSC: mockBsc.url,
      ALPHASHIELD_RPC_URL_ETHEREUM: mockEth.url,
    });
    try {
      // 3a. With PUBLIC_BASE_URL configured, matching Host + attacker Origin MUST NOT fall back to Host!
      const forgedHostAndOrigin = await rawWireRequest(srv.baseUrl, "/api/auth/register", {
        method: "POST",
        headers: {
          host: "evil.attacker.com",
          origin: "http://evil.attacker.com",
        },
        bodyObj: {
          org_name: "Attacker",
          email: "atk@evil.test",
          password: "attacker-password-123",
        },
      });
      assert.equal(forgedHostAndOrigin.status, 403, "Host fallback must NOT authorize attacker Origin when PUBLIC_BASE_URL is set");

      // Browser request missing Origin & Referer on login/register is rejected (403)
      const missingBrowserOrigin = await rawWireRequest(srv.baseUrl, "/api/auth/login", {
        method: "POST",
        headers: {
          "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
          "sec-fetch-site": "cross-site",
        },
        bodyObj: { email: "user@test.local", password: "password1234" },
      });
      assert.equal(missingBrowserOrigin.status, 403, "Browser login without Origin/Referer must be blocked");

      // Register valid session using canonical PUBLIC_BASE_URL origin
      const agent = createBrowserAgent(srv.baseUrl, "https://studio.rea.security");
      const reg = await agent.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "Finality Trader",
          email: "trader@finality.test",
          password: "trader-password-1234",
        }),
      });
      assert.equal(reg.status, 200);

      // 3b. AlphaShield free-tier quota is enforced SERVER-SIDE (3/day limit; 4th scan returns 402 regardless of localStorage)
      const sampleBytecode = "6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea264697066735822";
      for (let i = 1; i <= 2; i += 1) {
        const evmScan = await agent.request("/api/alphashield/evm-audit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ bytecode: sampleBytecode }),
        });
        assert.equal(evmScan.status, 200, `Free scan #${i} should succeed`);
      }
      // 3rd free scan via SafeAPK endpoint
      const apkScan3 = await agent.request("/api/alphashield/apk-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          filename: "wallet-helper.apk",
          size_bytes: 32,
          sample_base64: Buffer.from("PK\x03\x04 META-INF/MANIFEST.MF").toString("base64"),
        }),
      });
      assert.equal(apkScan3.status, 200, "Free scan #3 should succeed");
      assert.equal(apkScan3.body.tenant.usage.alphashield_scans_today, 3);

      // 4th scan attempt (even if attacker cleared browser localStorage!) MUST be blocked with HTTP 402
      const bypassedEvm4 = await agent.request("/api/alphashield/evm-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ bytecode: sampleBytecode }),
      });
      assert.equal(bypassedEvm4.status, 402);
      assert.equal(bypassedEvm4.body.error?.code, "alphashield_quota_exceeded");

      const bypassedApk4 = await agent.request("/api/alphashield/apk-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          filename: "second.apk",
          size_bytes: 32,
          sample_base64: Buffer.from("PK\x03\x04 classes.dex").toString("base64"),
        }),
      });
      assert.equal(bypassedApk4.status, 402);

      // Verify client JS no longer gates scans via localStorage consumeScanCredit()
      const alphaClientJs = readFileSync(join(REPO_ROOT, "studio/alphashield/app.js"), "utf8");
      assert.equal(alphaClientJs.includes("consumeScanCredit"), false);

      // 3c. Chain-specific confirmation depth: BSC requires >= 15 confirmations; Ethereum requires >= 12 confirmations
      const payerWallet = "0x3333333333333333333333333333333333333333";
      const bscIntentRes = await agent.request("/api/alphashield/payment-intent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chain: "bsc",
          plan_id: "alphashield_pro",
          charge_period: "MONTHLY",
          payer_wallet: payerWallet,
        }),
      });
      assert.equal(bscIntentRes.status, 200);
      const bscIntent = bscIntentRes.body.intent;
      const bscTx = `0x${"b".repeat(64)}`;

      // Register BSC tx with only 14 confirmations (< 15 required) -> MUST reject 400 insufficient_confirmations
      mockBsc.setTransfer({
        txHash: bscTx,
        fromWallet: payerWallet,
        rawUnits: bscIntent.exact_raw_units,
        confirmations: 14,
      });
      const bscTooShallow = await agent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_id: bscIntent.intent_id, tx_hash: bscTx }),
      });
      assert.equal(bscTooShallow.status, 400);
      assert.equal(bscTooShallow.body.error?.code, "insufficient_confirmations");
      assert.equal(bscTooShallow.body.error?.required_confirmations, 15);

      // Reorged blockHash mismatch -> MUST reject 409 reorg_detected
      mockBsc.setTransfer({
        txHash: bscTx,
        fromWallet: payerWallet,
        rawUnits: bscIntent.exact_raw_units,
        confirmations: 16,
        reorged: true,
      });
      const bscReorged = await agent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_id: bscIntent.intent_id, tx_hash: bscTx }),
      });
      assert.equal(bscReorged.status, 409);
      assert.equal(bscReorged.body.error?.code, "reorg_detected");

      // Advance BSC tx to 15 canonical confirmations -> MUST succeed 200
      mockBsc.setTransfer({
        txHash: bscTx,
        fromWallet: payerWallet,
        rawUnits: bscIntent.exact_raw_units,
        confirmations: 15,
        reorged: false,
      });
      const bscFinalized = await agent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_id: bscIntent.intent_id, tx_hash: bscTx }),
      });
      assert.equal(bscFinalized.status, 200);

      // Ethereum finality check: 11 confirmations rejected, 12 confirmations accepted
      const ethIntentRes = await agent.request("/api/alphashield/payment-intent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chain: "ethereum",
          plan_id: "alphashield_whale",
          charge_period: "MONTHLY",
          payer_wallet: payerWallet,
        }),
      });
      assert.equal(ethIntentRes.status, 200);
      const ethIntent = ethIntentRes.body.intent;
      const ethTx = `0x${"e".repeat(64)}`;

      mockEth.setTransfer({
        txHash: ethTx,
        fromWallet: payerWallet,
        rawUnits: ethIntent.exact_raw_units,
        confirmations: 11,
      });
      const ethTooShallow = await agent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_id: ethIntent.intent_id, tx_hash: ethTx }),
      });
      assert.equal(ethTooShallow.status, 400);
      assert.equal(ethTooShallow.body.error?.code, "insufficient_confirmations");
      assert.equal(ethTooShallow.body.error?.required_confirmations, 12);

      mockEth.setTransfer({
        txHash: ethTx,
        fromWallet: payerWallet,
        rawUnits: ethIntent.exact_raw_units,
        confirmations: 12,
      });
      const ethFinalized = await agent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent_id: ethIntent.intent_id, tx_hash: ethTx }),
      });
      assert.equal(ethFinalized.status, 200);
    } finally {
      await srv.stop();
    }

    // Production missing Origin check (NODE_ENV=production rejects missing Origin even without browser UA)
    const prodSrv = await startServerInstance({
      NODE_ENV: "production",
      PUBLIC_BASE_URL: "https://studio.rea.security",
    });
    try {
      const noOriginProd = await rawWireRequest(prodSrv.baseUrl, "/api/auth/register", {
        method: "POST",
        headers: {},
        bodyObj: {
          org_name: "No Origin",
          email: "noorigin@prod.test",
          password: "prod-password-1234",
        },
      });
      assert.equal(noOriginProd.status, 403, "Production must reject auth requests missing Origin and Referer");
    } finally {
      await prodSrv.stop();
    }
  });

  // =========================================================================
  // 4. F-04, F-05 & F-06: Evidence Digest Verification, Cross-Tenant Isolation & Concurrent ZIP Reservations
  // =========================================================================
  await t.test("F-04, F-05 & F-06: Verifies exported .evidence.json digests, isolates tenant memory/RL caps, reserves concurrent ZIP bytes, and refunds all failed quotas", async () => {
    const [{ parseEvidence, evidenceSemanticContent }, { digestCanonicalValue }] = await Promise.all([
      import(join(REPO_ROOT, "dist/domain/evidence.js")),
      import(join(REPO_ROOT, "dist/domain/canonicalDigest.js")),
    ]);

    // 4a. Direct engine test for cross-tenant Evidence fairness, MCP BinarySession recycling & global RL cap
    const isoDir = mkdtempSync(join(tmpdir(), "rea-iso-engine-"));
    const isoEngine = new ReaStudioEngine(REPO_ROOT, isoDir, {
      maxEvidenceEntries: 8,
      maxEvidencePerTenant: 3,
      maxTenantSessions: 2,
      maxCallsPerTenantSession: 2,
      maxTenantLiveEnvs: 2,
      maxGlobalLiveEnvs: 2,
    });
    try {
      await isoEngine.init();
      const sampleAppPath = join(REPO_ROOT, "website/public/examples/notes-electron");
      const scanA = await isoEngine.scanJavaScriptApplication("ten_quiet_a", sampleAppPath, "QuietAppA");
      assert.equal(scanA.ok, true);

      // Noisy Tenant B runs 8 scans — must NOT evict Quiet Tenant A's Evidence AND must recycle MCP BinarySessions
      for (let i = 0; i < 8; i += 1) {
        const sb = await isoEngine.scanJavaScriptApplication("ten_noisy_b", sampleAppPath, `NoisyApp-${i}`);
        assert.equal(sb.ok, true);
      }

      assert.ok(
        isoEngine.getEvidenceRecord("ten_quiet_a", scanA.evidence_id) !== null,
        "Noisy Tenant B must NEVER evict Quiet Tenant A's Evidence from evidenceLedger",
      );
      assert.ok(isoEngine.listEvidence("ten_noisy_b").length <= 3, "Per-tenant Evidence cap enforced");
      assert.ok(isoEngine.metrics.mcp_sessions_recycled >= 3, "Bounded per-tenant BinarySessions recycled");

      // Even after Tenant A's BinarySession was evicted by Tenant B/C activity, traceJavaScriptFeature still works via inline Evidence!
      await isoEngine.scanJavaScriptApplication("ten_other_c", sampleAppPath, "OtherC");
      const traceAfterEviction = await isoEngine.traceJavaScriptFeature(
        "ten_quiet_a",
        scanA.evidence_id,
        "module",
        "main",
      );
      assert.equal(traceAfterEviction.ok, true, "Feature trace works even after MCP BinarySession rotation");
    } finally {
      await isoEngine.close();
      rmSync(isoDir, { recursive: true, force: true });
    }

    // 4b. Live HTTP server test for .evidence.json cryptographic verification, concurrent ZIP cap race, global RL cap & quota refunds
    const srv = await startServerInstance({
      REA_MAX_TENANT_UPLOAD_BYTES: String(180 * 1024), // 180 KiB cap for fast deterministic race proof
      REA_MAX_GLOBAL_RL_ENVS: "1",
      ALLOW_SANDBOX_BILLING: "true",
    });
    try {
      const agentA = createBrowserAgent(srv.baseUrl);
      await agentA.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "Tenant Alpha",
          email: "alpha@race.test",
          password: "alpha-password-1234",
        }),
      });
      // Upgrade Tenant Alpha to team in sandbox so scan quota (unlimited) doesn't mask the 180 KiB storage cap
      await agentA.request("/api/billing/confirm-sandbox", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan_id: "ai_lab" }),
      });

      // Scan Electron sample & verify exported .evidence.json passes core REA parseEvidence() + digest verification!
      const scanRes = await agentA.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "acme-desktop-v1" }),
      });
      assert.equal(scanRes.status, 200);
      const evId = scanRes.body.evidence_id;

      const detailRes = await agentA.request(`/api/evidence/${evId}`);
      assert.equal(detailRes.status, 200);
      assert.equal(detailRes.body.record.is_redacted, true);
      assert.notEqual(
        detailRes.body.record.evidence_id,
        detailRes.body.record.original_evidence_id,
        "Redacted export must NOT claim the unredacted original_evidence_id",
      );

      const exportedRes = await agentA.request(`/api/evidence/${evId}/report?format=json`);
      assert.equal(exportedRes.status, 200);
      const exportedJson = exportedRes.body;
      const expectedDigest = `ev_${digestCanonicalValue(evidenceSemanticContent(exportedJson), "Evidence")}`;
      assert.equal(exportedJson.evidence_id, expectedDigest, "Exported .evidence.json digest MUST verify");
      const parsedCore = parseEvidence(exportedJson);
      assert.equal(parsedCore.evidence_id, expectedDigest, "Exported .evidence.json MUST pass core REA parseEvidence()");
      assert.ok(
        exportedJson.limitations.some((l) => l.includes(detailRes.body.record.original_evidence_id)),
        "Redacted export limitations must disclose original sealed evidence_id",
      );

      // Verify standalone preview studio/index.html SNAPSHOT.evDetails also carry valid Evidence digests
      const previewHtml = readFileSync(join(REPO_ROOT, "studio/index.html"), "utf8");
      const snapMatch = previewHtml.match(/const SNAPSHOT = (\{[\s\S]*?\});\nlet STATIC_MODE/);
      assert.ok(snapMatch, "Located SNAPSHOT in studio/index.html");
      const snapObj = JSON.parse(snapMatch[1]);
      for (const rec of Object.values(snapObj.evDetails || {})) {
        const calcId = `ev_${digestCanonicalValue(evidenceSemanticContent(rec.evidence), "Evidence")}`;
        assert.equal(rec.evidence.evidence_id, calcId, "Embedded studio/index.html Evidence digest must verify");
      }

      // Concurrent ZIP extraction race proof: upload one ~62 KiB uncompressed Electron JS ZIP (~33 KiB compressed, ~1.9:1 ratio)
      // 180 KiB tenant cap allows at most TWO concurrent 62 KiB extractions (33 + 62 + 62 = 157 <= 180; 3rd = 219 > 180!)
      const entropyPayload = randomBytes(31_000).toString("hex");
      const zip68k = buildValidMultiFileZip([
        {
          name: "package.json",
          content: JSON.stringify({
            name: "concurrent-electron-app",
            version: "1.0.0",
            main: "index.js",
            dependencies: { electron: "^33.0.0" },
          }),
        },
        {
          name: "index.js",
          content: `const { BrowserWindow } = require("electron");\nconst ENTROPY_BLOB = "${entropyPayload}";\nnew BrowserWindow({ webPreferences: { sandbox: true, contextIsolation: true } });\n`,
        },
      ]);
      const upZip = await agentA.request("/api/upload", {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-filename": "concurrent68k.zip",
        },
        body: zip68k,
      });
      assert.equal(upZip.status, 200);

      // Fire 4 concurrent ZIP scan requests simultaneously!
      const raceResponses = await Promise.all(
        Array.from({ length: 4 }, () =>
          agentA.request("/api/xray/scan", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ saved_path: upZip.body.saved_path }),
          }),
        ),
      );
      const count200 = raceResponses.filter((r) => r.status === 200).length;
      const count429 = raceResponses.filter((r) => r.status === 429).length;
      assert.ok(count200 >= 1 && count200 <= 2, `Expected 1..2 concurrent extractions to fit under 180 KiB, got ${count200}`);
      assert.ok(count429 >= 2, `Expected >=2 concurrent extractions rejected with 429, got ${count429}`);

      // After all 4 settle, in-flight reservation must be cleanly released so a subsequent sequential scan succeeds!
      const sequentialAfterRace = await agentA.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upZip.body.saved_path }),
      });
      assert.equal(sequentialAfterRace.status, 200, "In-flight byte reservations must release cleanly in finally");

      // Global RL server cap (REA_MAX_GLOBAL_RL_ENVS=1) + quota refund on 503/422 failure!
      const rlA = await agentA.request("/api/rl/build", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "helpdesk-crm" }),
      });
      assert.equal(rlA.status, 200);

      // Register free-trial Tenant B (5 scans, 1 RL build) and test BOTH global RL capacity 503 refund AND invalid HAR/JS 422 quota refunds!
      const agentB = createBrowserAgent(srv.baseUrl);
      await agentB.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "Tenant Beta",
          email: "beta@quota.test",
          password: "beta-password-1234",
        }),
      });
      const bKey = agentB.getApiKey();

      // Tenant B tries RL build while Tenant A holds the sole global RL slot -> 503 AND rl_builds_used refunded to 0!
      const rlBlockedGlobal = await agentB.request("/api/rl/build", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "helpdesk-crm" }),
      });
      assert.equal(rlBlockedGlobal.status, 503);
      assert.equal(rlBlockedGlobal.body.error?.code, "global_rl_capacity_reached");
      assert.equal(rlBlockedGlobal.body.tenant.usage.rl_builds_used, 0, "Failed RL build must refund rl_builds_used");

      // Upload corrupt/non-HAR file for Tenant B and verify /api/rl/build & /api/v1/rl/build refund quota on 422!
      const badHarUp = await agentB.request("/api/upload", {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-filename": "corrupt.har",
        },
        body: Buffer.from("not-valid-json-har", "utf8"),
      });
      assert.equal(badHarUp.status, 200);

      const v1BadRl = await fetch(`${srv.baseUrl}/api/v1/rl/build`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${bKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ saved_path: badHarUp.body.saved_path }),
      });
      const v1BadRlJson = await v1BadRl.json();
      assert.ok(v1BadRl.status >= 400);
      assert.equal(v1BadRlJson.tenant.usage.rl_builds_used, 0, "/api/v1/rl/build must refund quota on failure");

      // Upload corrupt .asar archive and verify /api/xray/scan refunds scans_used on { ok: false } (422)!
      const badAsarUp = await agentB.request("/api/upload", {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-filename": "corrupt.asar",
        },
        body: Buffer.from("not-valid-asar-binary-header", "utf8"),
      });
      assert.equal(badAsarUp.status, 200);

      const failedXray = await agentB.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: badAsarUp.body.saved_path }),
      });
      assert.equal(failedXray.status, 422);
      assert.equal(failedXray.body.tenant.usage.scans_used, 0, "/api/xray/scan must refund scans_used on 422 { ok: false }");

      const failedShipgate = await agentB.request("/api/shipgate/inspect", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: badHarUp.body.saved_path, category: "ai-model" }),
      });
      assert.equal(failedShipgate.status, 422);
      assert.equal(failedShipgate.body.tenant.usage.scans_used, 0, "/api/shipgate/inspect must refund scans_used on 422");
    } finally {
      await srv.stop();
    }

    // 4c. Simulated SQLite write failure via RAISE(ABORT) trigger rolls back cleanly without corrupting DB
    const abortDir = createDurableTestDataRoot(join(REPO_ROOT, "studio"));
    try {
      const dbPath = join(abortDir, "studio.sqlite");
      const store = new TenantBillingStore(join(abortDir, "legacy.json"), { sqlitePath: dbPath });
      const reg = store.register({
        org_name: "Rollback Test",
        email: "rb@test.local",
        password: "rollback-password-123",
      });
      assert.equal(reg.ok, true);

      store.db.exec(`
        CREATE TRIGGER fail_billing_event_insert
        BEFORE INSERT ON billing_events
        BEGIN
          SELECT RAISE(ABORT, 'simulated_disk_or_constraint_write_failure');
        END;
      `);

      assert.throws(() => {
        store.applyPlanProvisioning(reg.tenant.id, "team", { source: "test" });
      }, /simulated_disk_or_constraint_write_failure/);

      // Verify atomic rollback: tenant plan_id was NOT partially updated to 'team'!
      const afterAbort = store.getTenantById(reg.tenant.id);
      assert.equal(afterAbort.plan_id, "free_trial", "Failed transaction must roll back partial tenant updates");
      store.close();
      assert.equal(verifySqliteBackup(dbPath).ok, true);
    } finally {
      rmSync(abortDir, { recursive: true, force: true });
    }
  });

  // =========================================================================
  // 5. F-10, F-11 & F-12: XSS Escaping, Genuine 404 Static Assets & 0700 Directory Permissions
  // =========================================================================
  await t.test("F-10, F-11 & F-12: Escapes RL tool/effect XSS payloads, returns 404 for missing static assets, and enforces 0700 runtime/data dirs", async () => {
    // 5a. Verify XSS fix in studio/public/app.js and studio/index.html
    const appJs = readFileSync(join(REPO_ROOT, "studio/public/app.js"), "utf8");
    const standaloneHtml = readFileSync(join(REPO_ROOT, "studio/index.html"), "utf8");
    assert.equal(appJs.includes("`${w.tool} (${w.effect})`"), false, "Unescaped w.tool/w.effect interpolation must be gone");
    assert.ok(appJs.includes("`${esc(w.tool)} (${esc(w.effect)})`"), "esc(w.tool) and esc(w.effect) must be used");
    assert.equal(standaloneHtml.includes("`${w.tool} (${w.effect})`"), false);

    // Execute exact escaping logic against malicious XSS payload
    const esc = (s) =>
      String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    const xssPayload = [{ tool: `<img src=x onerror=alert(1)>`, effect: `<svg onload=alert(2)>` }];
    const rendered = xssPayload.map((w) => `${esc(w.tool)} (${esc(w.effect)})`).join(", ");
    assert.equal(rendered.includes("<img"), false);
    assert.equal(rendered.includes("<svg"), false);
    assert.ok(rendered.includes("&lt;img src=x onerror=alert(1)&gt;"));

    // 5b. Verify .env.example lists supported BSC & ETHEREUM chains without unsupported POLYGON/ARBITRUM
    const envExample = readFileSync(join(REPO_ROOT, "studio/.env.example"), "utf8");
    assert.ok(envExample.includes("ALPHASHIELD_RPC_URL_BSC="));
    assert.ok(envExample.includes("ALPHASHIELD_RPC_URL_ETHEREUM="));
    assert.equal(envExample.includes("POLYGON"), false);
    assert.equal(envExample.includes("ARBITRUM"), false);

    // 5c. Live server check for genuine 404 on missing static assets + 0700 directory permissions
    const srv = await startServerInstance();
    try {
      for (const dir of [srv.runtimeDir, srv.dataDir, join(srv.runtimeDir, "bundles"), join(srv.runtimeDir, "uploads")]) {
        const mode = statSync(dir).mode & 0o777;
        assert.equal(mode, 0o700, `Expected 0700 permissions on ${dir}, got 0${mode.toString(8)}`);
      }

      for (const missingAsset of [
        "/missing-bundle.js",
        "/nonexistent.css",
        "/favicon-404.png",
        "/alphashield/ad.html",
        "/alphashield/missing-video.mp4",
      ]) {
        const r = await fetch(`${srv.baseUrl}${missingAsset}`);
        assert.equal(r.status, 404, `Missing static asset ${missingAsset} must return 404, not SPA 200 HTML`);
      }

      // Valid entrypoints still serve 200 HTML / JS cleanly
      const rootHtml = await fetch(`${srv.baseUrl}/`);
      assert.equal(rootHtml.status, 200);
      assert.match(rootHtml.headers.get("content-type") || "", /text\/html/);

      const alphaHtml = await fetch(`${srv.baseUrl}/alphashield`);
      assert.equal(alphaHtml.status, 200);
      assert.match(alphaHtml.headers.get("content-type") || "", /text\/html/);
    } finally {
      await srv.stop();
    }
  });

  // =========================================================================
  // 6. NF-01, NF-02, NF-03 & NF-04: Post-Audit Hardening & /tmp Portability
  // =========================================================================
  await t.test("NF-01, NF-02, NF-03 & NF-04: Fails closed 502 on missing eth_chainId, enforces concurrent APK storage reservation/release, returns 400 on malformed RL percent-encoding, and supports /tmp checkout portability", async () => {
    const MERCHANT_WALLET = "0x9999999999999999999999999999999999999999";
    const PAYER_WALLET = "0x1111111111111111111111111111111111111111";
    const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const padAddr = (a) => `0x${a.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;

    let chainIdMode = "http_500";
    let expectedAmountUnits = 0n;
    const blockHash = `0x${"ab".repeat(32)}`;
    const nowSec = Math.floor(Date.now() / 1000);

    const mockRpc = createServer(async (req, res) => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const sendRpc = (result) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      };

      if (body.method === "eth_chainId") {
        if (chainIdMode === "http_500") {
          res.writeHead(500);
          res.end("upstream_error");
          return;
        }
        if (chainIdMode === "rpc_null") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601, message: "Method unavailable" } }));
          return;
        }
        if (chainIdMode === "invalid_hex") {
          return sendRpc("not_a_chain_id");
        }
        return sendRpc("0x38"); // BSC 56
      }

      if (body.method === "eth_blockNumber") {
        return sendRpc("0x3e8"); // 1000
      }

      if (body.method === "eth_getTransactionReceipt") {
        return sendRpc({
          transactionHash: body.params[0],
          status: "0x1",
          blockNumber: "0x3d9", // 985 -> 15 confirmations
          blockHash,
          from: PAYER_WALLET,
          logs: [
            {
              address: "0x55d398326f99059ff775485246999027b3197955",
              topics: [TRANSFER_TOPIC, padAddr(PAYER_WALLET), padAddr(MERCHANT_WALLET)],
              data: `0x${expectedAmountUnits.toString(16).padStart(64, "0")}`,
            },
          ],
        });
      }

      if (body.method === "eth_getBlockByNumber") {
        return sendRpc({
          number: body.params[0],
          hash: blockHash,
          timestamp: `0x${nowSec.toString(16)}`,
        });
      }

      return sendRpc(null);
    });

    await new Promise((r) => mockRpc.listen(0, "127.0.0.1", r));
    const rpcUrl = `http://127.0.0.1:${mockRpc.address().port}`;

    const srv = await startServerInstance({
      REA_INSECURE_HTTP_DEV_COOKIES: "true",
      REA_MAX_TENANT_UPLOAD_BYTES: "95000", // 95 KB cap to exercise APK storage reservation
      ALPHASHIELD_ENABLE_DIRECT_USDT: "true",
      ALPHASHIELD_MERCHANT_WALLET: MERCHANT_WALLET,
      ALPHASHIELD_RPC_URL_BSC: rpcUrl,
    });

    try {
      // -------------------------------------------------------------------
      // 6a. NF-01: /api/alphashield/verify-tx fails closed 502 when eth_chainId is unavailable
      // -------------------------------------------------------------------
      const payerAgent = createBrowserAgent(srv.baseUrl);
      const regPayer = await payerAgent.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "NF01 Chain Guard Corp",
          email: "nf01@rea.test",
          password: "strong-password-1234",
        }),
      });
      assert.equal(regPayer.status, 200);

      const piRes = await payerAgent.request("/api/alphashield/payment-intent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chain: "bsc",
          plan_id: "alphashield_pro",
          charge_period: "MONTHLY",
          payer_wallet: PAYER_WALLET,
        }),
      });
      assert.equal(piRes.status, 200);
      expectedAmountUnits = BigInt(piRes.body.intent.exact_raw_units);
      const txHash = `0x${"ef".repeat(32)}`;

      for (const badMode of ["http_500", "rpc_null", "invalid_hex"]) {
        chainIdMode = badMode;
        const vFail = await payerAgent.request("/api/alphashield/verify-tx", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            intent_id: piRes.body.intent.intent_id,
            tx_hash: txHash,
          }),
        });
        assert.equal(vFail.status, 502, `Expected 502 for eth_chainId mode=${badMode}, got ${vFail.status}`);
        assert.equal(vFail.body.error?.code, "rpc_chain_id_unavailable");
      }

      // Restore healthy eth_chainId -> same intent & tx_hash redeem cleanly (proving nothing was burned on 502)
      chainIdMode = "valid_0x38";
      const vOk = await payerAgent.request("/api/alphashield/verify-tx", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intent_id: piRes.body.intent.intent_id,
          tx_hash: txHash,
        }),
      });
      assert.equal(vOk.status, 200);
      assert.equal(vOk.body.tenant.alphashield_plan_id, "alphashield_pro");

      // -------------------------------------------------------------------
      // 6b. NF-02: /api/alphashield/apk-audit enforces tenant storage reservation & guaranteed release
      // -------------------------------------------------------------------
      // Part 1: Free-tier user with 55 KB uploaded cannot exceed 95 KB via apk-audit AND retains 0 daily scans used
      const freeApkAgent = createBrowserAgent(srv.baseUrl);
      const regFreeApk = await freeApkAgent.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org_name: "NF02 Free Quota Org",
          email: "nf02-free@rea.test",
          password: "strong-password-1234",
        }),
      });
      assert.equal(regFreeApk.status, 200);

      const filler55k = Buffer.alloc(55_000, 0x41);
      const up55 = await freeApkAgent.request("/api/upload", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          filename: "filler.bin",
          base64: filler55k.toString("base64"),
        }),
      });
      assert.equal(up55.status, 200);

      const apkSample55k = Buffer.concat([Buffer.from("PK\x03\x04DEX"), Buffer.alloc(55_000, 0x42)]);
      const overCapRes = await freeApkAgent.request("/api/alphashield/apk-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          filename: "wallet.apk",
          sample_base64: apkSample55k.toString("base64"),
        }),
      });
      assert.equal(overCapRes.status, 429);
      assert.equal(overCapRes.body.error?.code, "tenant_storage_limit_exceeded");

      const bootFreeAfter = await freeApkAgent.request("/api/bootstrap");
      assert.equal(
        bootFreeAfter.body.tenant.usage.alphashield_scans_today,
        0,
        "Storage-rejected APK audit must not consume daily AlphaShield scan quota",
      );

      // Part 2: Pro user fires 6 concurrent 55 KB APK audits against 95 KB cap -> concurrent overflow rejected (429),
      // zero temp directories remain on disk, and immediate post-burst audit succeeds (200)
      const apkBurst = await Promise.all(
        Array.from({ length: 6 }, (_, idx) =>
          payerAgent.request("/api/alphashield/apk-audit", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              filename: `burst-${idx}.apk`,
              sample_base64: apkSample55k.toString("base64"),
            }),
          }),
        ),
      );
      const burstStatuses = apkBurst.map((r) => r.status);
      const apkOkCount = burstStatuses.filter((s) => s === 200).length;
      const apkCapCount = burstStatuses.filter((s) => s === 429).length;
      assert.ok(apkOkCount >= 1, `Expected at least 1 APK audit to succeed, got ${JSON.stringify(burstStatuses)}`);
      assert.ok(apkCapCount >= 1, `Expected concurrent APK storage cap 429s, got ${JSON.stringify(burstStatuses)}`);
      assert.equal(apkOkCount + apkCapCount, 6);

      const proTenantUploadsDir = join(srv.runtimeDir, "uploads", payerAgent.getTenant().id);
      if (existsSync(proTenantUploadsDir)) {
        const leftovers = readdirSync(proTenantUploadsDir).filter((name) => name.startsWith("apk-"));
        assert.deepEqual(leftovers, [], "Temporary apk-* scratch slots must be cleaned up");
      }

      const postBurstApk = await payerAgent.request("/api/alphashield/apk-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          filename: "post-burst.apk",
          sample_base64: apkSample55k.toString("base64"),
        }),
      });
      assert.equal(postBurstApk.status, 200, "Guaranteed reservation release must allow immediate sequential APK audit");

      // -------------------------------------------------------------------
      // 6c. NF-03: Malformed percent-encoding in RL download URLs returns 400 (never 500)
      // -------------------------------------------------------------------
      const malformedSegments = ["%E0%A4%A", "%ZZ", "%", "bad%2Gid", "env%2F..%2Fsecret"];
      for (const seg of malformedSegments) {
        const browserBad = await payerAgent.request(`/api/rl/download/${seg}`);
        assert.equal(
          browserBad.status,
          400,
          `Expected 400 on /api/rl/download/${seg}, got ${browserBad.status}`,
        );
        assert.match(browserBad.body.error?.code || "", /^(malformed_url_encoding|invalid_rl_env_id)$/);

        const v1Bad = await fetch(`${srv.baseUrl}/api/v1/rl/download/${seg}`, {
          headers: { authorization: `Bearer ${payerAgent.getApiKey()}` },
        });
        const v1Json = await v1Bad.json();
        assert.equal(
          v1Bad.status,
          400,
          `Expected 400 on /api/v1/rl/download/${seg}, got ${v1Bad.status}`,
        );
        assert.match(v1Json.error?.code || "", /^(malformed_url_encoding|invalid_rl_env_id)$/);
      }

      // Valid RL download still returns 200 application/zip
      const rlBuilt = await payerAgent.request("/api/rl/build", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "helpdesk-crm" }),
      });
      assert.equal(rlBuilt.status, 200);
      const validDl = await fetch(
        `${srv.baseUrl}/api/rl/download/${encodeURIComponent(rlBuilt.body.env_id)}`,
        { headers: { cookie: payerAgent.getCookie() } },
      );
      assert.equal(validDl.status, 200);
      assert.match(validDl.headers.get("content-type") || "", /application\/zip/);
    } finally {
      await srv.stop();
      await new Promise((r) => mockRpc.close(r));
    }

    // -------------------------------------------------------------------
    // 6d. NF-04: Production-mode test helper works when repo is checked out under /tmp
    //            WITHOUT weakening production /tmp REA_STUDIO_DATA_DIR rejection
    // -------------------------------------------------------------------
    const tmpCheckout = mkdtempSync(join(tmpdir(), "rea-tmp-checkout-"));
    try {
      for (const topEntry of ["package.json", "node_modules", "dist", "bridge", "licenses"]) {
        if (existsSync(join(REPO_ROOT, topEntry))) {
          symlinkSync(join(REPO_ROOT, topEntry), join(tmpCheckout, topEntry));
        }
      }
      mkdirSync(join(tmpCheckout, "studio"), { recursive: true });
      for (const studioCopy of ["package.json", "server", "public", "alphashield", "scripts"]) {
        if (existsSync(join(REPO_ROOT, "studio", studioCopy))) {
          cpSync(join(REPO_ROOT, "studio", studioCopy), join(tmpCheckout, "studio", studioCopy), {
            recursive: true,
          });
        }
      }
      if (existsSync(join(REPO_ROOT, "studio", "node_modules"))) {
        symlinkSync(join(REPO_ROOT, "studio", "node_modules"), join(tmpCheckout, "studio", "node_modules"));
      }

      // Verify production /tmp storage protection is NOT weakened when run from a real /tmp checkout
      // (both default DATA_DIR under /tmp checkout AND explicit /tmp path must fail closed!)
      const defaultTmpFail = spawnSync(process.execPath, ["studio/server/index.mjs"], {
        cwd: tmpCheckout,
        env: {
          ...process.env,
          NODE_ENV: "production",
          PUBLIC_BASE_URL: "https://tmp-checkout.rea.test",
          REA_STUDIO_DATA_DIR: "",
          PORT: "0",
        },
        encoding: "utf8",
        timeout: 8000,
      });
      assert.notEqual(defaultTmpFail.status, 0, "Production server must reject default /tmp checkout DATA_DIR");
      assert.match(defaultTmpFail.stderr, /ephemeral \/tmp storage/i);

      // Verify startServerInstance helper succeeds from /tmp checkout in NODE_ENV=production
      const tmpSrv = await startServerInstance(
        {
          NODE_ENV: "production",
          PUBLIC_BASE_URL: "https://tmp-checkout.rea.test",
        },
        { cwdOverride: tmpCheckout },
      );
      try {
        assert.equal(
          isEphemeralTmpLocation(tmpSrv.dataDir),
          false,
          `Expected helper dataDir outside /tmp, got ${tmpSrv.dataDir}`,
        );
        const hRes = await fetch(`${tmpSrv.baseUrl}/api/health`);
        assert.equal(hRes.status, 200);

        const prodAgent = createBrowserAgent(tmpSrv.baseUrl, "https://tmp-checkout.rea.test");
        const regProd = await prodAgent.request("/api/auth/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            org_name: "Tmp Checkout Prod Org",
            email: "tmpprod@rea.test",
            password: "strong-password-1234",
          }),
        });
        assert.equal(regProd.status, 200);
      } finally {
        await tmpSrv.stop();
      }
    } finally {
      rmSync(tmpCheckout, { recursive: true, force: true });
    }
  });
});
