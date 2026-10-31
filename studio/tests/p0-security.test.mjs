import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { promisify } from "node:util";
import { deflateRawSync } from "node:zlib";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

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

/**
 * Minimal raw ZIP builder for testing traversal, symlink, and single-entry zip-bomb defenses.
 */
function buildRawZipEntry({
  name,
  uncompressedBuf,
  compressionMethod = 8,
  externalAttrs = 0,
  spoofUncompressedSize = null,
}) {
  const nameBuf = Buffer.from(name, "utf8");
  const compressedBuf =
    compressionMethod === 8 ? deflateRawSync(uncompressedBuf, { level: 9 }) : uncompressedBuf;
  const crc = crc32(uncompressedBuf);
  const uncompSize = spoofUncompressedSize ?? uncompressedBuf.length;

  const localHeader = Buffer.alloc(30 + nameBuf.length);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(compressionMethod, 8);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(compressedBuf.length, 18);
  localHeader.writeUInt32LE(uncompSize, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  nameBuf.copy(localHeader, 30);

  const centralOffset = localHeader.length + compressedBuf.length;
  const centralHeader = Buffer.alloc(46 + nameBuf.length);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE((3 << 8) | 20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(compressionMethod, 10);
  centralHeader.writeUInt32LE(crc, 16);
  centralHeader.writeUInt32LE(compressedBuf.length, 20);
  centralHeader.writeUInt32LE(uncompSize, 24);
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt32LE(externalAttrs >>> 0, 38);
  centralHeader.writeUInt32LE(0, 42);
  nameBuf.copy(centralHeader, 46);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralHeader.length, 12);
  eocd.writeUInt32LE(centralOffset, 16);

  return Buffer.concat([localHeader, compressedBuf, centralHeader, eocd]);
}

/**
 * Constructs a Fifield-style overlapping ZIP bomb where multiple Central Directory
 * headers reference the exact same local header / compressed DEFLATE kernel.
 */
function buildOverlappingZipBomb(entryCount = 20) {
  const payload = Buffer.alloc(32 * 1024, 0x41);
  const comp = deflateRawSync(payload, { level: 9 });
  const crc = crc32(payload);
  const sharedName = Buffer.from("shared.js", "utf8");

  const localHeader = Buffer.alloc(30 + sharedName.length);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(8, 8);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(comp.length, 18);
  localHeader.writeUInt32LE(payload.length, 22);
  localHeader.writeUInt16LE(sharedName.length, 26);
  sharedName.copy(localHeader, 30);

  const cdParts = [];
  for (let i = 0; i < entryCount; i += 1) {
    const cdName = Buffer.from(`clone-${i}.js`, "utf8");
    const cd = Buffer.alloc(46 + cdName.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE((3 << 8) | 20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(8, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(comp.length, 20);
    cd.writeUInt32LE(payload.length, 24);
    cd.writeUInt16LE(cdName.length, 28);
    cd.writeUInt32LE(0, 42); // Reuses localHeaderOffset = 0!
    cdName.copy(cd, 46);
    cdParts.push(cd);
  }
  const cdAll = Buffer.concat(cdParts);
  const cdOffset = localHeader.length + comp.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entryCount, 8);
  eocd.writeUInt16LE(entryCount, 10);
  eocd.writeUInt32LE(cdAll.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);

  return Buffer.concat([localHeader, comp, cdAll, eocd]);
}

/**
 * Constructs a multi-entry small-file ratio bomb where each entry is only 6 KiB (< old 64 KiB check)
 * but compresses at >200:1 ratio across 10 entries.
 */
function buildSmallEntriesRatioBomb() {
  const localParts = [];
  const cdParts = [];
  let offset = 0;
  const count = 10;

  for (let i = 0; i < count; i += 1) {
    const uncomp = Buffer.alloc(6144, 0); // 6 KiB zeros -> ~18 bytes deflated (>300:1 ratio!)
    const comp = deflateRawSync(uncomp, { level: 9 });
    const crc = crc32(uncomp);
    const name = Buffer.from(`small-${i}.js`, "utf8");

    const lfh = Buffer.alloc(30 + name.length);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(8, 8);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(comp.length, 18);
    lfh.writeUInt32LE(uncomp.length, 22);
    lfh.writeUInt16LE(name.length, 26);
    name.copy(lfh, 30);

    const cd = Buffer.alloc(46 + name.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE((3 << 8) | 20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(8, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(comp.length, 20);
    cd.writeUInt32LE(uncomp.length, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE(offset, 42);
    name.copy(cd, 46);

    localParts.push(lfh, comp);
    cdParts.push(cd);
    offset += lfh.length + comp.length;
  }

  const cdAll = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cdAll.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdAll, eocd]);
}

function buildValidJsZip(files) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;
  const entries = Object.entries(files);
  for (const [filename, content] of entries) {
    const uncomp = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
    const name = Buffer.from(filename, "utf8");
    const crc = crc32(uncomp);

    const lfh = Buffer.alloc(30 + name.length);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0, 8); // stored (1:1 ratio)
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(uncomp.length, 18);
    lfh.writeUInt32LE(uncomp.length, 22);
    lfh.writeUInt16LE(name.length, 26);
    name.copy(lfh, 30);

    const cd = Buffer.alloc(46 + name.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE((3 << 8) | 20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(uncomp.length, 20);
    cd.writeUInt32LE(uncomp.length, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE(offset, 42);
    name.copy(cd, 46);

    localParts.push(lfh, uncomp);
    cdParts.push(cd);
    offset += lfh.length + uncomp.length;
  }
  const cdAll = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdAll.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, cdAll, eocd]);
}

/**
 * Dynamic programmable mock BSC JSON-RPC server so tests can register exact
 * `(txHash, fromWallet, toWallet, tokenAddr, rawAmountBigInt, ageSec)` transfers.
 */
async function startMockBscRpc(merchantWallet) {
  const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const OFFICIAL_BSC_USDT = "0x55d398326f99059ff775485246999027b3197955";
  const txRegistry = new Map();

  let headBlockOffset = 20;
  let chainIdHex = "0x38";
  const setHeadBlockOffset = (n) => {
    headBlockOffset = Number(n);
  };
  const setChainIdHex = (hex) => {
    chainIdHex = String(hex);
  };

  const registerTransfer = ({
    txHash,
    fromWallet,
    toWallet = merchantWallet,
    tokenAddress = OFFICIAL_BSC_USDT,
    rawUnits,
    ageSec = 10,
    confirmations = null,
    blockHash = null,
    canonicalBlockHash = null,
  }) => {
    const cleanTx = txHash.toLowerCase();
    const blkNum = 0x100 + txRegistry.size;
    const blkHex = `0x${blkNum.toString(16)}`;
    const txBlkHash = blockHash || `0x${blkNum.toString(16).padStart(64, "a")}`;
    const paddedFrom = `0x${fromWallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
    const paddedTo = `0x${toWallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
    const dataHex = `0x${BigInt(rawUnits).toString(16).padStart(64, "0")}`;
    txRegistry.set(cleanTx, {
      blockNum: blkNum,
      blockNumber: blkHex,
      ageSec,
      confirmations,
      canonicalBlockHash: canonicalBlockHash || txBlkHash,
      receipt: {
        status: "0x1",
        blockNumber: blkHex,
        blockHash: txBlkHash,
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

  const rpcServer = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const reply = (result) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      };

      if (body.method === "eth_chainId") {
        return reply(chainIdHex);
      }

      if (body.method === "eth_blockNumber") {
        let latest = 0x100 + headBlockOffset;
        for (const rec of txRegistry.values()) {
          const targetHead =
            rec.confirmations !== null && rec.confirmations !== undefined
              ? rec.blockNum + Number(rec.confirmations)
              : rec.blockNum + headBlockOffset;
          latest = targetHead;
        }
        return reply(`0x${Math.max(0, latest).toString(16)}`);
      }

      if (body.method === "eth_getTransactionReceipt") {
        const tx = String(body.params?.[0] || "").toLowerCase();
        return reply(txRegistry.get(tx)?.receipt || null);
      }

      if (body.method === "eth_getBlockByNumber") {
        const blk = body.params?.[0];
        let ageSec = 10;
        let blkHash = `0x${String(blk || "0x0").replace(/^0x/, "").padStart(64, "a")}`;
        for (const rec of txRegistry.values()) {
          if (rec.blockNumber === blk) {
            ageSec = rec.ageSec;
            blkHash = rec.canonicalBlockHash;
            break;
          }
        }
        const ts = Math.floor(Date.now() / 1000) - ageSec;
        return reply({ number: blk, hash: blkHash, timestamp: `0x${ts.toString(16)}` });
      }

      return reply(null);
    });
  });

  await new Promise((r) => rpcServer.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${rpcServer.address().port}`,
    OFFICIAL_BSC_USDT,
    registerTransfer,
    setHeadBlockOffset,
    setChainIdHex,
    close: () => new Promise((r) => rpcServer.close(r)),
  };
}

/**
 * Mock Kelviq API server supporting `/license/validate/`, `/license/activate/`,
 * `/customers/...`, and `/checkout/...` so `@kelviq/node-sdk` executes real HTTP calls.
 */
async function startMockKelviqServer() {
  const licenses = new Map();
  let lastCheckoutPayload = null;

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
        if (!rec) return send(200, { valid: false, detail: "Unknown license key" });
        return send(200, { valid: true, license: rec });
      }
      if (req.url?.includes("/license/activate")) {
        const key = body.license_key || body.licenseKey;
        const rec = licenses.get(key);
        if (!rec) return send(400, { detail: "Unknown license key" });
        return send(200, {
          activated: true,
          instanceId: `inst_${randomBytes(4).toString("hex")}`,
          expiresOn: rec.expiresOn,
          license: rec,
        });
      }
      if (req.url?.includes("/customers")) {
        return send(200, { id: body.customer_id || body.customerId || "cus_ok" });
      }
      if (req.url?.includes("/checkout")) {
        lastCheckoutPayload = body;
        const retUrl = body.success_url || body.successUrl || "";
        return send(200, {
          checkoutSessionId: "kvq_cs_live_mock",
          checkoutUrl: `https://pay.kelviq.test/session?return=${encodeURIComponent(retUrl)}`,
        });
      }
      return send(200, { ok: true });
    });
  });

  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${srv.address().port}`,
    licenses,
    getLastCheckoutPayload: () => lastCheckoutPayload,
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

async function startStudioTestServer(envOverrides = {}, preseedStore = null, options = {}) {
  const effectiveRepoRoot = options.cwdOverride ? resolve(options.cwdOverride) : REPO_ROOT;
  const rootTmp = mkdtempSync(join(tmpdir(), "rea-sprint2-test-"));
  const persistentTestRoot = createDurableTestDataRoot(join(effectiveRepoRoot, "studio"));
  const runtimeDir = join(rootTmp, "runtime");
  const dataDir = envOverrides.REA_STUDIO_DATA_DIR || join(persistentTestRoot, "data");

  if (preseedStore) {
    mkdirSync(dataDir, { recursive: true });
    const storeFile = join(dataDir, "tenant-store.json");
    writeFileSync(storeFile, JSON.stringify(preseedStore, null, 2));
    chmodSync(storeFile, 0o644);
  }

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
    rmSync(persistentTestRoot, { recursive: true, force: true });
    throw new Error(`Studio server failed to start on ${baseUrl}:\n${logs}`);
  }

  return {
    baseUrl,
    dataDir,
    runtimeDir,
    getLogs: () => logs,
    stop: async () => {
      proc.kill("SIGTERM");
      await new Promise((r) => proc.once("exit", r));
      rmSync(rootTmp, { recursive: true, force: true });
      rmSync(persistentTestRoot, { recursive: true, force: true });
    },
  };
}

/**
 * Helper session client simulating a real browser with `Cookie: rea_session=...` + `X-CSRF-Token`.
 */
function createSessionAgent(baseUrl) {
  let cookie = "";
  let csrfToken = "";
  let tenant = null;
  let apiKey = "";

  const request = async (path, opts = {}) => {
    const method = String(opts.method || "GET").toUpperCase();
    const skipCsrf = Boolean(opts.skipCsrf);
    const headers = {
      ...(cookie ? { cookie } : {}),
      ...(method !== "GET" && method !== "HEAD" && !skipCsrf && csrfToken
        ? { "x-csrf-token": csrfToken }
        : {}),
      ...(opts.headers || {}),
    };
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: opts.body,
    });
    const setCookie = res.headers.get("set-cookie");
    if (setCookie) {
      const pair = setCookie.split(";")[0];
      cookie = pair.endsWith("=") ? "" : pair;
    }
    const ct = res.headers.get("content-type") || "";
    const body = ct.includes("application/json") ? await res.json() : await res.text();
    if (body && typeof body === "object") {
      if (typeof body.csrf_token === "string" && body.csrf_token) csrfToken = body.csrf_token;
      if (body.tenant) tenant = body.tenant;
      if (body.starter_api_key?.secret_token) apiKey = body.starter_api_key.secret_token;
    }
    return { status: res.status, headers: res.headers, body, setCookie };
  };

  return {
    request,
    getCookie: () => cookie,
    getCsrf: () => csrfToken,
    getTenant: () => tenant,
    getApiKey: () => apiKey,
  };
}

async function jsonReq(baseUrl, path, opts = {}) {
  const res = await fetch(`${baseUrl}${path}`, opts);
  const body = await res.json();
  return { status: res.status, headers: res.headers, body };
}

test("Second Security Remediation Suite — Full Phase 1 & Phase 2 Adversarial Verification", async (t) => {
  const TEST_MERCHANT_WALLET = "0x1234567890abcdef1234567890abcdef12345678";
  const TEST_STRIPE_WEBHOOK_SECRET = "whsec_test_stripe_secret_key_p0";
  const rawKelviqSecretBytes = randomBytes(32);
  const TEST_KELVIQ_WEBHOOK_SECRET = `whsec_${rawKelviqSecretBytes.toString("base64")}`;

  const mockRpc = await startMockBscRpc(TEST_MERCHANT_WALLET);
  const mockKelviq = await startMockKelviqServer();

  const legacySeed = {
    version: 1,
    default_tenant_id: "ten_founder_demo",
    tenants: {
      ten_founder_demo: {
        id: "ten_founder_demo",
        email: "founder@acme-security.dev",
        org_name: "Acme AppSec Workspace",
        password_salt: "deadbeef",
        password_hash: "deadbeef",
        plan_id: "team",
        api_keys: [{ id: "key_demo", name: "Demo", token: "rea_sk_live_compromised_demo", calls: 0 }],
      },
      ten_legacy_cust: {
        id: "ten_legacy_cust",
        email: "legacy@cust.io",
        org_name: "Legacy Customer",
        password_salt: "00",
        password_hash: "00",
        plan_id: "indie",
        api_keys: [
          { id: "key_leg", name: "Legacy CI", token: "rea_sk_live_plaintext_legacy_key_12345", calls: 2 },
        ],
      },
    },
    sessions: {},
    billing_events: [],
  };

  const srv = await startStudioTestServer(
    {
      ALPHASHIELD_MERCHANT_WALLET: TEST_MERCHANT_WALLET,
      ALPHASHIELD_ENABLE_DIRECT_USDT: "true",
      ALPHASHIELD_RPC_URL_BSC: mockRpc.url,
      STRIPE_WEBHOOK_SECRET: TEST_STRIPE_WEBHOOK_SECRET,
      KELVIQ_WEBHOOK_SECRET: TEST_KELVIQ_WEBHOOK_SECRET,
      KELVIQ_SERVER_API_KEY: "kvq_test_mock_key_non_secret",
      KELVIQ_API_BASE_URL: mockKelviq.url,
      CORS_ALLOWED_ORIGINS: "https://app.example.com",
    },
    legacySeed,
  );

  t.after(async () => {
    await srv.stop();
    await mockRpc.close();
    await mockKelviq.close();
  });

  // -------------------------------------------------------------------------
  // 1. SQLite WAL Migration, 0600 Permissions, Strict CSP (No unsafe-inline) & Unmounted Side Apps
  // -------------------------------------------------------------------------
  await t.test("1. Migrates legacy JSON into 0600 SQLite WAL, enforces strict CSP without unsafe-inline, and unmounts /solidcraft & /canvix", async () => {
    const sqlitePath = join(srv.dataDir, "studio.sqlite");
    assert.equal(existsSync(sqlitePath), true, "studio.sqlite must exist");
    assert.equal(statSync(sqlitePath).mode & 0o777, 0o600, "studio.sqlite must be chmod 0600");

    // Migrated legacy API key works via SHA-256 hash; demo account purged
    const v1Status = await jsonReq(srv.baseUrl, "/api/v1/status", {
      headers: { authorization: "Bearer rea_sk_live_plaintext_legacy_key_12345" },
    });
    assert.equal(v1Status.status, 200);
    assert.equal(v1Status.body.organization, "Legacy Customer");

    const demoLogin = await jsonReq(srv.baseUrl, "/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "founder@acme-security.dev", password: "demo-password-123" }),
    });
    assert.equal(demoLogin.status, 401);

    // CSP on / and /alphashield has script-src 'self' WITHOUT 'unsafe-inline'
    for (const page of ["/", "/alphashield"]) {
      const pageRes = await fetch(`${srv.baseUrl}${page}`);
      assert.equal(pageRes.status, 200);
      const csp = pageRes.headers.get("content-security-policy") || "";
      assert.ok(csp.includes("script-src 'self'"), `Missing script-src 'self' on ${page}: ${csp}`);
      assert.equal(csp.includes("script-src 'self' 'unsafe-inline'"), false, `unsafe-inline must be removed from script-src on ${page}`);
      const html = await pageRes.text();
      assert.equal(/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), false, `Zero inline <script> blocks allowed in ${page}`);
      assert.equal(/\son[a-z]+\s*=/i.test(html), false, `Zero inline on*= handlers allowed in ${page}`);
    }

    const alphaAppJs = await fetch(`${srv.baseUrl}/alphashield/app.js`);
    assert.equal(alphaAppJs.status, 200);

    // /solidcraft and /canvix return 404 while source files remain untouched on disk
    for (const removedRoute of ["/solidcraft", "/solidcraft/", "/canvix", "/canvix/"]) {
      const r = await fetch(`${srv.baseUrl}${removedRoute}`);
      assert.equal(r.status, 404, `Expected 404 on ${removedRoute}, got ${r.status}`);
    }
    assert.equal(existsSync(join(REPO_ROOT, "studio/solidcraft/index.html")), true);
    assert.equal(existsSync(join(REPO_ROOT, "studio/canvix/index.html")), true);

    // Unauthenticated /api/kelviq/status MUST NOT disclose merchant_wallet
    const kvqStatus = await jsonReq(srv.baseUrl, "/api/kelviq/status");
    assert.equal(kvqStatus.status, 200);
    assert.equal("merchant_wallet" in kvqStatus.body.kelviq, false, "merchant_wallet must not be disclosed in public status");
  });

  // -------------------------------------------------------------------------
  // 2. Strict 401 Enforcement Across All Protected Endpoints
  // -------------------------------------------------------------------------
  await t.test("2. Rejects unauthenticated calls across all protected routes including payment-intent", async () => {
    const dummyEv = `ev_${"0".repeat(64)}`;
    const protectedCalls = [
      ["GET", "/api/auth/me"],
      ["GET", "/api/evidence"],
      ["GET", `/api/evidence/${dummyEv}`],
      ["GET", `/api/evidence/${dummyEv}/report?format=md`],
      ["GET", "/api/rl/download/env_fake"],
      ["POST", "/api/upload"],
      ["POST", "/api/xray/scan"],
      ["POST", "/api/xray/trace"],
      ["POST", "/api/xray/compare"],
      ["POST", "/api/shipgate/inspect"],
      ["POST", "/api/rl/build"],
      ["POST", "/api/rl/call"],
      ["POST", "/api/rl/reset"],
      ["POST", "/api/rl/grade-task"],
      ["POST", "/api/keys/create"],
      ["POST", "/api/keys/revoke"],
      ["POST", "/api/billing/checkout"],
      ["POST", "/api/billing/confirm-sandbox"],
      ["POST", "/api/kelviq/checkout"],
      ["POST", "/api/kelviq/license/activate"],
      ["POST", "/api/kelviq/portal"],
      ["POST", "/api/alphashield/payment-intent"],
      ["POST", "/api/alphashield/verify-tx"],
      ["POST", "/api/alphashield/evm-audit"],
    ];

    for (const [method, path] of protectedCalls) {
      const r = await fetch(`${srv.baseUrl}${path}`, {
        method,
        headers: method === "POST" ? { "content-type": "application/json" } : {},
        body: method === "POST" ? "{}" : undefined,
      });
      assert.equal(r.status, 401, `Expected 401 on unauthenticated ${method} ${path}, got ${r.status}`);
    }
  });

  // -------------------------------------------------------------------------
  // 3. HttpOnly; Secure; SameSite=Lax Cookies, CSRF Enforcement, Origin Check & Isolation
  // -------------------------------------------------------------------------
  const agentA = createSessionAgent(srv.baseUrl);
  const agentB = createSessionAgent(srv.baseUrl);

  await t.test("3. Enforces HttpOnly; Secure; SameSite=Lax cookies, CSRF + Origin protection, and multi-tenant isolation", async () => {
    const regA = await agentA.request("/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ org_name: "Alpha Corp", email: "sec@alpha.test", password: "alpha-strong-pass" }),
    });
    assert.equal(regA.status, 200);
    assert.equal(regA.body.session_token, undefined, "Session token must NEVER be returned in JSON body");
    assert.equal(regA.body._cookie_session_token, undefined);
    assert.ok(regA.setCookie?.includes("rea_session="));
    assert.ok(regA.setCookie?.includes("HttpOnly"));
    assert.ok(regA.setCookie?.includes("Secure"));
    assert.ok(regA.setCookie?.includes("SameSite=Lax"));
    assert.ok(regA.body.csrf_token?.length >= 32);

    // Verify frontend JS files never store session tokens in localStorage
    const studioAppJs = readFileSync(join(REPO_ROOT, "studio/public/app.js"), "utf8");
    const alphaAppJs = readFileSync(join(REPO_ROOT, "studio/alphashield/app.js"), "utf8");
    assert.equal(studioAppJs.includes('setItem("rea_studio_session"'), false);
    assert.equal(alphaAppJs.includes('setItem("rea_studio_session"'), false);

    const regB = await agentB.request("/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ org_name: "Bravo Corp", email: "sec@bravo.test", password: "bravo-strong-pass" }),
    });
    assert.equal(regB.status, 200);

    // State-changing cookie request WITHOUT X-CSRF-Token -> 403 csrf_validation_failed
    const missingCsrf = await agentA.request("/api/keys/create", {
      method: "POST",
      skipCsrf: true,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "CSRF Bypass Attempt" }),
    });
    assert.equal(missingCsrf.status, 403);
    assert.equal(missingCsrf.body.error.code, "csrf_validation_failed");

    // State-changing cookie request WITH cross-site Origin -> 403 cross_origin_forbidden
    const evilOrigin = await agentA.request("/api/keys/create", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil-csrf.attacker.example" },
      body: JSON.stringify({ name: "Cross Origin Attempt" }),
    });
    assert.equal(evilOrigin.status, 403);
    assert.equal(evilOrigin.body.error.code, "cross_origin_forbidden");

    // Valid cookie + valid X-CSRF-Token scan succeeds and redacts all host paths
    const scanA = await agentA.request("/api/xray/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sample_id: "acme-desktop-v1" }),
    });
    assert.equal(scanA.status, 200);
    const evIdA = scanA.body.evidence_id;

    // Cross-tenant Evidence & retained-evidence MCP isolation
    assert.equal((await agentB.request(`/api/evidence/${evIdA}`)).status, 404);
    assert.equal(
      (
        await agentB.request("/api/xray/trace", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ evidence_id: evIdA, seed_kind: "channel", seed_value: "shell" }),
        })
      ).status,
      404,
    );

    // Unknown target in /api/xray/compare returns 404 (no silent fallback to sample!)
    const badCompare = await agentA.request("/api/xray/compare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ left: "nonexistent-target-xyz", right: "acme-desktop-v2" }),
    });
    assert.equal(badCompare.status, 404);
  });

  // -------------------------------------------------------------------------
  // 4. Phase 1.1: AlphaShield USDT Front-Running Defense & Subscription Expiry Enforcement
  // -------------------------------------------------------------------------
  await t.test("4. Blocks Tenant B front-running Tenant A's USDT payment, blocks unrelated transfers, and enforces subscription expiry", async () => {
    const walletA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const walletB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const randomOutsiderWallet = "0xcccccccccccccccccccccccccccccccccccccccc";

    // Tenant A creates a bound payment intent
    const intentResA = await agentA.request("/api/alphashield/payment-intent", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chain: "bsc",
        plan_id: "alphashield_pro",
        charge_period: "MONTHLY",
        payer_wallet: walletA,
      }),
    });
    assert.equal(intentResA.status, 200);
    const intentA = intentResA.body.intent;
    assert.equal(intentResA.body.merchant_wallet, TEST_MERCHANT_WALLET);

    // Tenant B creates their own payment intent -> gets a DIFFERENT unique atomic amount!
    const intentResB = await agentB.request("/api/alphashield/payment-intent", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chain: "bsc",
        plan_id: "alphashield_pro",
        charge_period: "MONTHLY",
        payer_wallet: walletB,
      }),
    });
    assert.equal(intentResB.status, 200);
    const intentB = intentResB.body.intent;
    assert.notEqual(
      intentA.exact_raw_units,
      intentB.exact_raw_units,
      "Concurrent intents must allocate distinct sub-cent atomic amounts",
    );

    // Tenant A broadcasts valid on-chain payment matching walletA + exact_raw_units
    const txA = `0x${"a1".repeat(32)}`;
    mockRpc.registerTransfer({
      txHash: txA,
      fromWallet: walletA,
      toWallet: TEST_MERCHANT_WALLET,
      rawUnits: intentA.exact_raw_units,
      ageSec: 5,
    });

    // Attack 1a: Tenant B observes txA in mempool/chain and tries to claim using Tenant A's intent_id -> 403!
    const frontRunStealIntent = await agentB.request("/api/alphashield/verify-tx", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent_id: intentA.intent_id, tx_hash: txA }),
    });
    assert.equal(frontRunStealIntent.status, 403);
    assert.equal(frontRunStealIntent.body.error.code, "payment_intent_tenant_mismatch");

    // Attack 1b: Tenant B tries to claim Tenant A's txA against Tenant B's own intent_id -> 400 (sender & exact amount mismatch)!
    const frontRunOwnIntent = await agentB.request("/api/alphashield/verify-tx", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent_id: intentB.intent_id, tx_hash: txA }),
    });
    assert.equal(frontRunOwnIntent.status, 400);
    assert.equal(frontRunOwnIntent.body.error.code, "intent_transfer_mismatch");

    // Attack 2: Attacker B submits an unrelated $25 USDT transfer sent to merchantWallet by randomOutsiderWallet -> 400!
    const unrelatedTx = `0x${"d2".repeat(32)}`;
    mockRpc.registerTransfer({
      txHash: unrelatedTx,
      fromWallet: randomOutsiderWallet,
      toWallet: TEST_MERCHANT_WALLET,
      rawUnits: (25n * 10n ** 18n).toString(),
      ageSec: 5,
    });
    const unrelatedClaim = await agentB.request("/api/alphashield/verify-tx", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent_id: intentB.intent_id, tx_hash: unrelatedTx }),
    });
    assert.equal(unrelatedClaim.status, 400);
    assert.equal(unrelatedClaim.body.error.code, "intent_transfer_mismatch");

    // Legitimate Tenant A verifies txA -> 200 OK with non-null alphashield_expires_at!
    const legitClaimA = await agentA.request("/api/alphashield/verify-tx", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent_id: intentA.intent_id, tx_hash: txA }),
    });
    assert.equal(legitClaimA.status, 200);
    assert.equal(legitClaimA.body.tenant.alphashield_plan_id, "alphashield_pro");
    assert.ok(Date.parse(legitClaimA.body.tenant.alphashield_expires_at) > Date.now());

    // Attack 3: Expire Tenant A's AlphaShield plan in SQLite and verify unlimited scans are immediately revoked!
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(join(srv.dataDir, "studio.sqlite"));
    db.prepare("UPDATE tenants SET alphashield_expires_at = ? WHERE id = ?").run(
      new Date(Date.now() - 60_000).toISOString(),
      agentA.getTenant().id,
    );
    db.close();

    // Exhaust the 3 free daily scans, then the 4th scan MUST be rejected with 402!
    for (let i = 0; i < 3; i += 1) {
      const r = await agentA.request("/api/alphashield/evm-audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ bytecode: "6080604052600080fd" }),
      });
      assert.equal(r.status, 200);
    }
    const fourthScan = await agentA.request("/api/alphashield/evm-audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bytecode: "6080604052600080fd" }),
    });
    assert.equal(fourthScan.status, 402, "Expired monthly AlphaShield plan must revert to 3/day free limit");
    assert.equal(fourthScan.body.error.code, "alphashield_quota_exceeded");
  });

  // -------------------------------------------------------------------------
  // 5. Phase 1.2: Kelviq Cancellation Without planIdentifier, Unknown Plans & License Anti-Sharing
  // -------------------------------------------------------------------------
  await t.test("5. Downgrades Studio ai_lab on Kelviq cancellation without planIdentifier, rejects unknown plans, and blocks license key sharing", async () => {
    const signKelviqWebhook = (id, payloadObj) => {
      const ts = String(Math.floor(Date.now() / 1000));
      const bodyStr = JSON.stringify(payloadObj);
      const sig = createHmac("sha256", rawKelviqSecretBytes)
        .update(`${id}.${ts}.${bodyStr}`)
        .digest("base64");
      return {
        headers: {
          "webhook-id": id,
          "webhook-timestamp": ts,
          "webhook-signature": `v1,${sig}`,
        },
        body: bodyStr,
      };
    };

    // Attack 5a: Unknown Kelviq plan in webhook is rejected (400), NEVER defaulted to AlphaShield!
    const unknownHook = signKelviqWebhook("wh_unknown_plan_1", {
      type: "subscription.created",
      data: {
        customerId: agentB.getTenant().id,
        planIdentifier: "totally-unrecognized-sku-999",
        subscriptionId: "sub_unknown_999",
      },
    });
    const unknownRes = await jsonReq(srv.baseUrl, "/api/webhooks/kelviq", {
      method: "POST",
      headers: unknownHook.headers,
      body: unknownHook.body,
    });
    assert.equal(unknownRes.status, 400);
    assert.equal(unknownRes.body.error.code, "unknown_kelviq_plan");

    // Provision Studio ai_lab for Tenant B via Kelviq webhook with subscriptionId
    const createStudioSub = signKelviqWebhook("wh_studio_ailab_create", {
      type: "subscription.created",
      data: {
        customerId: agentB.getTenant().id,
        planIdentifier: "rea-ai-lab",
        subscriptionId: "kvq_sub_studio_ailab_77",
      },
    });
    const provRes = await jsonReq(srv.baseUrl, "/api/webhooks/kelviq", {
      method: "POST",
      headers: createStudioSub.headers,
      body: createStudioSub.body,
    });
    assert.equal(provRes.status, 200);
    assert.equal((await agentB.request("/api/auth/me")).body.tenant.plan_id, "ai_lab");

    // Attack 4: Kelviq cancellation webhook arrives WITHOUT planIdentifier (only subscriptionId + customerId)
    const cancelNoPlan = signKelviqWebhook("wh_studio_ailab_cancel", {
      type: "subscription.cancelled",
      data: {
        customerId: agentB.getTenant().id,
        subscriptionId: "kvq_sub_studio_ailab_77",
      },
    });
    const cancelRes = await jsonReq(srv.baseUrl, "/api/webhooks/kelviq", {
      method: "POST",
      headers: cancelNoPlan.headers,
      body: cancelNoPlan.body,
    });
    assert.equal(cancelRes.status, 200);
    assert.equal(
      (await agentB.request("/api/auth/me")).body.tenant.plan_id,
      "free_trial",
      "Studio ai_lab subscription MUST downgrade to free_trial even when planIdentifier is omitted",
    );

    // Attack 6: License Key Ownership, Expiry & Cross-Tenant Sharing Prevention
    const futureExpiry = new Date(Date.now() + 14 * 86_400_000).toISOString();
    const pastExpiry = new Date(Date.now() - 86_400_000).toISOString();

    mockKelviq.licenses.set("KVQ-LIC-ALPHA-ONLY", {
      key: "KVQ-LIC-ALPHA-ONLY",
      customerId: agentA.getTenant().id,
      customerEmail: agentA.getTenant().email,
      expiresOn: futureExpiry,
      plan: { identifier: "alphashield-whale" },
    });
    mockKelviq.licenses.set("KVQ-LIC-EXPIRED", {
      key: "KVQ-LIC-EXPIRED",
      customerId: agentA.getTenant().id,
      expiresOn: pastExpiry,
      plan: { identifier: "alphashield-pro" },
    });
    mockKelviq.licenses.set("KVQ-LIC-UNBOUND-ONCE", {
      key: "KVQ-LIC-UNBOUND-ONCE",
      expiresOn: futureExpiry,
      plan: { identifier: "alphashield-pro" },
    });

    // Expired license rejected -> 400
    const expLicRes = await agentA.request("/api/kelviq/license/activate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ license_key: "KVQ-LIC-EXPIRED" }),
    });
    assert.equal(expLicRes.status, 400);
    assert.equal(expLicRes.body.error.code, "license_expired");

    // Tenant B attempts to activate a license owned by Tenant A's customerId -> 403!
    const mismatchRes = await agentB.request("/api/kelviq/license/activate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ license_key: "KVQ-LIC-ALPHA-ONLY" }),
    });
    assert.equal(mismatchRes.status, 403);
    assert.equal(mismatchRes.body.error.code, "license_customer_mismatch");

    // Tenant A activates KVQ-LIC-UNBOUND-ONCE -> 200 OK; Tenant B then tries to share the same key -> 409!
    const actFirst = await agentA.request("/api/kelviq/license/activate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ license_key: "KVQ-LIC-UNBOUND-ONCE" }),
    });
    assert.equal(actFirst.status, 200);
    assert.equal(actFirst.body.tenant.alphashield_plan_id, "alphashield_pro");

    const actSharedByB = await agentB.request("/api/kelviq/license/activate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ license_key: "KVQ-LIC-UNBOUND-ONCE" }),
    });
    assert.equal(actSharedByB.status, 409);
    assert.equal(actSharedByB.body.error.code, "license_already_bound");
  });

  // -------------------------------------------------------------------------
  // 6. Phase 1.3: Overlapping ZIP Bombs, Small-Entry Ratio Bombs, Pre-Quota Unpack & Rollback
  // -------------------------------------------------------------------------
  await t.test("6. Rejects overlapping & small-entry ZIP bombs, enforces quota BEFORE extraction across all 3 X-Ray endpoints, rolls back on error, and cleans up temp dirs", async () => {
    const regZipUser = createSessionAgent(srv.baseUrl);
    await regZipUser.request("/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ org_name: "Zip Lab", email: "zip@lab.test", password: "zip-strong-password" }),
    });

    // Attack 7a: Fifield-style overlapping-entry ZIP bomb -> 400 AND quota refunded (0/5 used!)
    const overlapZip = buildOverlappingZipBomb(16);
    const upOverlap = await regZipUser.request("/api/upload", {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "x-filename": "overlap-bomb.zip" },
      body: overlapZip,
    });
    assert.equal(upOverlap.status, 200);

    const scanOverlap = await regZipUser.request("/api/xray/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ saved_path: upOverlap.body.saved_path }),
    });
    assert.equal(scanOverlap.status, 400);
    assert.match(scanOverlap.body.error.message, /duplicate local header offset|Overlapping ZIP/i);

    // Attack 7b: Multi-entry small-file (< 64 KiB each) >100:1 ratio bomb -> 400 AND quota refunded!
    const smallRatioZip = buildSmallEntriesRatioBomb();
    const upSmallBomb = await regZipUser.request("/api/upload", {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "x-filename": "small-ratio-bomb.zip" },
      body: smallRatioZip,
    });
    const scanSmallBomb = await regZipUser.request("/api/xray/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ saved_path: upSmallBomb.body.saved_path }),
    });
    assert.equal(scanSmallBomb.status, 400);
    assert.match(scanSmallBomb.body.error.message, /zip bomb blocked/i);

    // Verify quota was refunded after both failed extractions AND zero unpacked-* dirs remain!
    const meAfterBombs = await regZipUser.request("/api/auth/me");
    assert.equal(meAfterBombs.body.tenant.usage.scans_used, 0, "Failed ZIP validations must refund scan quota");

    const tenantUploadRoot = join(srv.runtimeDir, "uploads", regZipUser.getTenant().id);
    for (const slot of readdirSync(tenantUploadRoot)) {
      const children = readdirSync(join(tenantUploadRoot, slot));
      assert.equal(
        children.some((c) => c.startsWith("unpacked")),
        false,
        `No leftover unpacked temp directory allowed in ${slot}: ${children}`,
      );
    }

    // Valid stored JS ZIP scans cleanly AND deletes its unpacked-* temp directory in finally!
    const validZip = buildValidJsZip({
      "package.json": JSON.stringify({ name: "clean-zip-app", version: "1.0.0", main: "index.js" }),
      "index.js": `const { BrowserWindow } = require("electron"); new BrowserWindow({ webPreferences: { sandbox: true, contextIsolation: true } });\n`,
    });
    const upValid = await regZipUser.request("/api/upload", {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "x-filename": "valid-app.zip" },
      body: validZip,
    });
    const scanValid = await regZipUser.request("/api/xray/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ saved_path: upValid.body.saved_path }),
    });
    assert.equal(scanValid.status, 200);
    assert.equal(scanValid.body.tenant.usage.scans_used, 1);

    // Exhaust the remaining 4 free scans (total 5/5)
    for (let i = 0; i < 4; i += 1) {
      const s = await regZipUser.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "acme-desktop-v1" }),
      });
      assert.equal(s.status, 200);
    }

    // Attack 8: Out-of-quota tenant uploads a corrupt ZIP — ALL THREE endpoints (/api/xray/scan, /api/xray/compare, /api/v1/xray)
    // MUST return 402 Quota Exceeded BEFORE attempting ZIP extraction (if extraction ran first, they would return 400)!
    const upCorrupt = await regZipUser.request("/api/upload", {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "x-filename": "corrupt-probe.zip" },
      body: Buffer.from("NOT_A_VALID_ZIP_HEADER_PROBE"),
    });
    assert.equal(upCorrupt.status, 200);

    const quotaScan = await regZipUser.request("/api/xray/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ saved_path: upCorrupt.body.saved_path }),
    });
    assert.equal(quotaScan.status, 402, "/api/xray/scan must reject out-of-quota BEFORE unpacking ZIP");

    const quotaCompare = await regZipUser.request("/api/xray/compare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ left: upCorrupt.body.saved_path, right: "acme-desktop-v2" }),
    });
    assert.equal(quotaCompare.status, 402, "/api/xray/compare must reject out-of-quota BEFORE unpacking ZIP");

    const quotaV1 = await jsonReq(srv.baseUrl, "/api/v1/xray", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${regZipUser.getApiKey()}`,
      },
      body: JSON.stringify({ saved_path: upCorrupt.body.saved_path }),
    });
    assert.equal(quotaV1.status, 402, "/api/v1/xray must reject out-of-quota BEFORE unpacking ZIP");

    // Direct unit check on extractZipSafely enforcing real-time tenant disk cap during extraction
    const { extractZipSafely } = await import("../server/index.mjs");
    const capTmp = mkdtempSync(join(tmpdir(), "rea-zip-cap-"));
    const zipFile = join(capTmp, "big.zip");
    writeFileSync(zipFile, buildValidJsZip({ "big.js": Buffer.alloc(64 * 1024, 0x61) }));
    await assert.rejects(
      () =>
        extractZipSafely(zipFile, join(capTmp, "out"), {
          initialTenantBytes: 90 * 1024,
          maxTenantDiskBytes: 120 * 1024, // 90 KiB + 64 KiB > 120 KiB cap -> rejected!
        }),
      /Workspace storage limit/,
    );
    rmSync(capTmp, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // 7. Phase 2.6: Filesystem-Path Redaction Across Evidence, Markdown, RL ZIP & Standalone HTML
  // -------------------------------------------------------------------------
  await t.test("7. Redacts local_path, runtime dirs, temp dirs, and tenant IDs across Evidence API, Markdown, RL ZIP, and studio/index.html", async () => {
    // Binary inspection (including objdump disassembly stdout) + RL bundle build
    const binRes = await agentA.request("/api/shipgate/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sample_id: "libvault-elf" }),
    });
    assert.equal(binRes.status, 200);
    const binStr = JSON.stringify(binRes.body);
    assert.equal(binStr.includes(srv.runtimeDir), false, "ShipGate response must not leak runtimeDir");
    assert.equal(/\/tmp\/|\/home\//.test(binStr), false, "ShipGate response must not leak /tmp or /home");

    const rlRes = await agentA.request("/api/rl/build", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sample_id: "helpdesk-crm", name: "clean-path-env" }),
    });
    assert.equal(rlRes.status, 200);
    const rlStr = JSON.stringify({ ...rlRes.body, tenant: null });
    assert.equal(rlStr.includes(srv.runtimeDir), false);
    assert.equal(rlStr.includes(agentA.getTenant().id), false, "RL response must not leak tenant ID in paths");
    assert.equal(/\/tmp\/|\/home\//.test(rlStr), false);

    // Download RL .zip and verify raw zip bytes contain zero /tmp/, /home/, runtimeDir, or tenantId strings
    const zipDownload = await fetch(
      `${srv.baseUrl}/api/rl/download/${encodeURIComponent(rlRes.body.env_id)}`,
      { headers: { cookie: agentA.getCookie() } },
    );
    assert.equal(zipDownload.status, 200);
    const zipText = Buffer.from(await zipDownload.arrayBuffer()).toString("utf8");
    assert.equal(zipText.includes(srv.runtimeDir), false, "RL .zip must not contain runtimeDir");
    assert.equal(zipText.includes(agentA.getTenant().id), false, "RL .zip must not contain tenant ID");
    assert.equal(/\/tmp\/|\/home\//.test(zipText), false, "RL .zip must not contain host paths");

    // Inspect every stored Evidence envelope + Markdown report for Tenant A
    const evList = await agentA.request("/api/evidence");
    assert.ok(evList.body.records.length >= 3);
    for (const item of evList.body.records) {
      const detail = await agentA.request(`/api/evidence/${item.evidence_id}`);
      assert.equal(detail.status, 200);
      const detailJson = JSON.stringify(detail.body);
      assert.equal(detailJson.includes("local_path"), false, `local_path must be stripped from ${item.evidence_id}`);
      assert.equal(detailJson.includes("caller_input_path"), false);
      assert.equal(detail.body.record.evidence.environment, null);
      assert.equal(/\/tmp\/|\/home\//.test(detailJson), false);

      const mdResp = await fetch(
        `${srv.baseUrl}/api/evidence/${item.evidence_id}/report?format=md`,
        { headers: { cookie: agentA.getCookie() } },
      );
      const mdText = await mdResp.text();
      assert.equal(/\/tmp\/|\/home\//.test(mdText), false);
    }

    // Verify studio/index.html contains zero build/host paths
    const standaloneHtml = readFileSync(join(REPO_ROOT, "studio/index.html"), "utf8");
    assert.equal(/\/home\/user|rea-preview-build-|unpacked-/.test(standaloneHtml), false);
  });

  // -------------------------------------------------------------------------
  // 8. Phase 1.4: PUBLIC_BASE_URL Fail-Closed in Prod, Host Poisoning, XFF Proxy Hops & 50k Bounded Limiter
  // -------------------------------------------------------------------------
  await t.test("8. Fails closed in production without PUBLIC_BASE_URL, blocks Host/X-Forwarded-Host poisoning, resists XFF spoofing, and bounds rate limiter under 50,000 keys", async () => {
    const rawPostWithHeaders = (targetBaseUrl, path, headers, payloadObj) =>
      new Promise((resolveRaw, rejectRaw) => {
        const u = new URL(path, targetBaseUrl);
        const bodyStr = JSON.stringify(payloadObj);
        const req = httpRequest(
          {
            hostname: u.hostname,
            port: u.port,
            path: u.pathname,
            method: "POST",
            headers: {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(bodyStr),
              ...headers,
            },
          },
          (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              resolveRaw({
                status: res.statusCode,
                body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
              });
            });
          },
        );
        req.on("error", rejectRaw);
        req.write(bodyStr);
        req.end();
      });

    // 8a. Spoofed Host / X-Forwarded-Host on raw wire in dev mode is rejected (400 untrusted_host_header)
    const poisonedDevCheckout = await rawPostWithHeaders(
      srv.baseUrl,
      "/api/kelviq/checkout",
      {
        cookie: agentA.getCookie(),
        "x-csrf-token": agentA.getCsrf(),
        host: "evil.attacker.com",
        "x-forwarded-host": "evil.attacker.com",
        origin: "http://evil.attacker.com",
      },
      { plan_id: "alphashield_pro" },
    );
    assert.equal(poisonedDevCheckout.status, 400, "Poisoned Host header must be rejected");
    assert.equal(poisonedDevCheckout.body.error.code, "untrusted_host_header");

    // 8b. Production server WITHOUT PUBLIC_BASE_URL fails closed (503) on checkout; WITH PUBLIC_BASE_URL ignores Host/X-Forwarded-Host
    const prodNoUrlSrv = await startStudioTestServer({
      NODE_ENV: "production",
      PUBLIC_BASE_URL: "",
      CORS_ALLOWED_ORIGINS: "https://console.rea.security",
      KELVIQ_SERVER_API_KEY: "kvq_test_prod_key",
      KELVIQ_API_BASE_URL: mockKelviq.url,
    });
    try {
      const prodAgent = createSessionAgent(prodNoUrlSrv.baseUrl);
      await prodAgent.request("/api/auth/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://console.rea.security",
        },
        body: JSON.stringify({ org_name: "Prod Org", email: "p@prod.test", password: "prod-password-123" }),
      });
      const failClosedRes = await prodAgent.request("/api/kelviq/checkout", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://console.rea.security",
        },
        body: JSON.stringify({ plan_id: "alphashield_pro" }),
      });
      assert.equal(failClosedRes.status, 503, "Production checkout without PUBLIC_BASE_URL must fail closed (503)");
    } finally {
      await prodNoUrlSrv.stop();
    }

    const prodWithUrlSrv = await startStudioTestServer({
      NODE_ENV: "production",
      PUBLIC_BASE_URL: "https://studio.rea.security",
      KELVIQ_SERVER_API_KEY: "kvq_test_prod_key",
      KELVIQ_API_BASE_URL: mockKelviq.url,
    });
    try {
      const prodAgent2 = createSessionAgent(prodWithUrlSrv.baseUrl);
      await prodAgent2.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://studio.rea.security" },
        body: JSON.stringify({ org_name: "Prod2", email: "p2@prod.test", password: "prod-password-123" }),
      });
      const safeRedirectRes = await rawPostWithHeaders(
        prodWithUrlSrv.baseUrl,
        "/api/kelviq/checkout",
        {
          cookie: prodAgent2.getCookie(),
          "x-csrf-token": prodAgent2.getCsrf(),
          origin: "https://studio.rea.security",
          host: "evil-redirect.attacker.org",
          "x-forwarded-host": "evil-redirect.attacker.org",
        },
        { plan_id: "alphashield_pro" },
      );
      assert.equal(safeRedirectRes.status, 200);
      const lastPayload = mockKelviq.getLastCheckoutPayload();
      const recordedSuccessUrl = lastPayload?.success_url || lastPayload?.successUrl || "";
      assert.ok(
        recordedSuccessUrl.startsWith("https://studio.rea.security/"),
        `Checkout successUrl must strictly use PUBLIC_BASE_URL, got: ${recordedSuccessUrl}`,
      );
    } finally {
      await prodWithUrlSrv.stop();
    }

    // 8c. Spoofed X-Forwarded-For CANNOT bypass auth rate limit AND locking out target1@victim.test does NOT lock out sec@alpha.test on same IP!
    let saw429WithSpoofedXff = false;
    for (let i = 0; i < 16; i += 1) {
      const r = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": `198.51.100.${i + 1}`,
        },
        body: JSON.stringify({ email: "target1@victim.test", password: "wrong-password" }),
      });
      if (r.status === 429) {
        saw429WithSpoofedXff = true;
        break;
      }
    }
    assert.equal(saw429WithSpoofedXff, true, "Rotating spoofed X-Forwarded-For must NOT bypass auth rate limit");

    // Different legitimate user on the SAME client IP is NOT locked out!
    const otherUserLogin = await jsonReq(srv.baseUrl, "/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "sec@alpha.test", password: "alpha-strong-pass" }),
    });
    assert.equal(otherUserLogin.status, 200, "Brute-forcing one email must not lock out a different email on shared NAT IP");

    // 8d. Unit-verify BoundedRateLimiter under 50,000 unique active keys & trusted-proxy hop parsing
    const { BoundedRateLimiter, getClientIp } = await import("../server/index.mjs");
    const bounded = new BoundedRateLimiter(5, 60_000, 512);
    const fixedNow = Date.now();
    for (let i = 0; i < 50_000; i += 1) {
      bounded.check(`attacker-key-${i}`, fixedNow);
    }
    assert.equal(
      bounded.buckets.size,
      512,
      `Rate limiter map must never exceed maxBuckets (512), got ${bounded.buckets.size}`,
    );

    // Trusted proxy right-to-left hop verification
    const prevTrusted = process.env.TRUSTED_PROXY_IPS;
    const prevHops = process.env.TRUSTED_PROXY_HOPS;
    try {
      process.env.TRUSTED_PROXY_IPS = "10.0.0.5";
      process.env.TRUSTED_PROXY_HOPS = "1";
      // Attacker spoofs 1.1.1.1 on the left; real client is 203.0.113.9; proxy is 10.0.0.5
      const parsedIp = getClientIp({
        socket: { remoteAddress: "10.0.0.5" },
        headers: { "x-forwarded-for": "1.1.1.1, 203.0.113.9" },
      });
      assert.equal(parsedIp, "203.0.113.9", "Must extract rightmost untrusted hop, ignoring spoofed leftmost XFF");

      // Direct untrusted peer sending XFF is completely ignored
      const untrustedIp = getClientIp({
        socket: { remoteAddress: "192.0.2.55" },
        headers: { "x-forwarded-for": "1.1.1.1, 203.0.113.9" },
      });
      assert.equal(untrustedIp, "192.0.2.55");
    } finally {
      if (prevTrusted === undefined) delete process.env.TRUSTED_PROXY_IPS;
      else process.env.TRUSTED_PROXY_IPS = prevTrusted;
      if (prevHops === undefined) delete process.env.TRUSTED_PROXY_HOPS;
      else process.env.TRUSTED_PROXY_HOPS = prevHops;
    }
  });

  // -------------------------------------------------------------------------
  // 9. Phase 2.7 + CLI + Logout: Concurrent SQLite Persistence, Bounded Eviction, Reapers & CLI
  // -------------------------------------------------------------------------
  await t.test("9. Preserves 100% of concurrent SQLite writes, bounds Evidence memory, reaps expired uploads/idle RL servers, supports CLI, and invalidates session on logout", async () => {
    // 9a. CI CLI end-to-end compatibility via Bearer API key
    const safeJsFile = join(srv.runtimeDir, "clean-cli-test.js");
    writeFileSync(
      safeJsFile,
      `const { BrowserWindow } = require("electron"); new BrowserWindow({ webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true } });\n`,
    );
    const cliRun = await execFileAsync("node", ["studio/ci/shipgate-cli.mjs", "xray", safeJsFile], {
      cwd: REPO_ROOT,
      env: { ...process.env, REA_STUDIO_URL: srv.baseUrl, REA_API_KEY: agentA.getApiKey() },
    });
    assert.ok(cliRun.stdout.includes("[APPROVED]"));

    // 9b. Logout invalidates server session AND clears cookie
    const savedCookieBeforeLogout = agentA.getCookie();
    const savedCsrfBeforeLogout = agentA.getCsrf();
    const logoutRes = await agentA.request("/api/auth/logout", { method: "POST" });
    assert.equal(logoutRes.status, 200);
    assert.equal(logoutRes.body.revoked, true);
    assert.ok(logoutRes.setCookie?.includes("Max-Age=0"));

    // Replaying the old cookie after logout MUST return 401!
    const replayOldCookie = await fetch(`${srv.baseUrl}/api/auth/me`, {
      headers: { cookie: savedCookieBeforeLogout, "x-csrf-token": savedCsrfBeforeLogout },
    });
    assert.equal(replayOldCookie.status, 401);

    // 9c. Concurrent SQLite persistence across two TenantBillingStore instances sharing one WAL DB (zero lost updates!)
    const { TenantBillingStore } = await import("../server/tenantBilling.mjs");
    const concDir = mkdtempSync(join(tmpdir(), "rea-sqlite-conc-"));
    const sqliteFile = join(concDir, "studio.sqlite");
    const store1 = new TenantBillingStore(join(concDir, "legacy.json"), { sqlitePath: sqliteFile });
    const store2 = new TenantBillingStore(join(concDir, "legacy.json"), { sqlitePath: sqliteFile });
    try {
      const reg = store1.register({
        org_name: "Concurrent Org",
        email: "conc@wal.test",
        password: "strong-wal-password",
      });
      assert.equal(reg.ok, true);
      store1.applyPlanProvisioning(reg.tenant.id, "ai_lab", { source: "test" });

      // Fire 30 concurrent operations alternating store1 and store2 (webhook IDs + quota increments + billing events)
      await Promise.all(
        Array.from({ length: 30 }, (_, idx) =>
          Promise.resolve().then(() => {
            const s = idx % 2 === 0 ? store1 : store2;
            s.markWebhookProcessed("stripe", `evt_conc_${idx}`);
            s.checkAndConsumeQuota({ id: reg.tenant.id }, "scan", 1);
          }),
        ),
      );

      for (let idx = 0; idx < 30; idx += 1) {
        assert.equal(
          store1.isWebhookProcessed("stripe", `evt_conc_${idx}`),
          true,
          `Webhook evt_conc_${idx} must not be lost under concurrent writes`,
        );
      }
      const refreshed = store2.getTenantById(reg.tenant.id);
      assert.equal(refreshed.scans_used, 30, "All 30 concurrent scan increments must be preserved atomically");
    } finally {
      store1.close();
      store2.close();
      rmSync(concDir, { recursive: true, force: true });
    }

    // 9d. Bounded Evidence LRU eviction + expired upload & idle RL reaper verification
    const { ReaStudioEngine } = await import("../server/reaEngine.mjs");
    const { pruneTenantUploads } = await import("../server/index.mjs");
    const reapDir = mkdtempSync(join(tmpdir(), "rea-reap-test-"));
    const boundedEng = new ReaStudioEngine(REPO_ROOT, reapDir, {
      maxEvidenceEntries: 4,
      rlIdleTtlMs: 1000,
    });
    const { ensureStudioSamples } = await import("../server/sampleFactory.mjs");
    const localSamples = ensureStudioSamples(REPO_ROOT, reapDir);
    try {
      await boundedEng.init();
      // Seal >4 Evidence records (ELF inspection seals 4+ envelopes, plus JS scan seals 1 more)
      await boundedEng.inspectShipGateArtifact("ten_reap", localSamples.binaryTargets[0].path);
      await boundedEng.scanJavaScriptApplication("ten_reap", localSamples.electronTargets[0].path);
      assert.ok(boundedEng.evidenceLedger.size <= 4, `Expected <=4 bounded ledger entries, got ${boundedEng.evidenceLedger.size}`);
      assert.ok(boundedEng.metrics.evidence_evicted >= 1);

      // Build live RL env, age its last_active_at, and verify reapIdleEnvironments shuts it down & deletes bundle_dir
      const rlBuilt = await boundedEng.buildAndServeAgentEnvironment(
        "ten_reap",
        localSamples.harTargets[0].path,
        "idle-test",
      );
      assert.equal(rlBuilt.ok, true);
      const liveRec = boundedEng.liveEnvironments.get(rlBuilt.env_id);
      const bundlePath = liveRec.bundle_dir;
      assert.equal(existsSync(bundlePath), true);
      liveRec.last_active_at = Date.now() - 5000;
      const reapedCount = await boundedEng.reapIdleEnvironments(1000);
      assert.equal(reapedCount, 1);
      assert.equal(boundedEng.liveEnvironments.size, 0);
      assert.equal(existsSync(bundlePath), false, "Idle RL bundle_dir must be deleted on reap");

      // Expired upload directory cleanup
      const fakeSlot = join(boundedEng.uploadsDir, "ten_reap", "1700000000000-deadbeefcafe");
      mkdirSync(fakeSlot, { recursive: true });
      writeFileSync(join(fakeSlot, "old.bin"), "stale");
      const oldTime = new Date(Date.now() - 2 * 3600 * 1000);
      utimesSync(fakeSlot, oldTime, oldTime);
      pruneTenantUploads(join(boundedEng.uploadsDir, "ten_reap"), Date.now(), 60_000);
      assert.equal(existsSync(fakeSlot), false, "Expired upload slot must be deleted by reaper");
    } finally {
      await boundedEng.close();
      rmSync(reapDir, { recursive: true, force: true });
    }
  });
});
