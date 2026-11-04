import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createServer, request as httpRequest } from "node:http";
import { promisify } from "node:util";
import { deflateRawSync } from "node:zlib";
import { DatabaseSync } from "node:sqlite";
import { createPackage as createAsarPackage } from "@electron/asar";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { buildZipBuffer, crc32 } from "../server/zipBuilder.mjs";
import { backupSqliteDatabase, restoreSqliteDatabase } from "../scripts/sqliteBackup.mjs";

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(import.meta.dirname, "../..");

function isEphemeralTmpLocation(dirPath) {
  let resolved;
  try {
    resolved = existsSync(dirPath) ? realpathSync(dirPath) : resolve(dirPath);
  } catch {
    resolved = resolve(dirPath);
  }
  const sysTmp = (() => {
    try {
      return realpathSync(tmpdir());
    } catch {
      return resolve(tmpdir());
    }
  })();
  const ephemeralRoots = Array.from(
    new Set(["/tmp", "/var/tmp", "/private/tmp", sysTmp].map((p) => p.replace(/\/+$/u, ""))),
  );
  return ephemeralRoots.some(
    (root) => root.length > 0 && (resolved === root || resolved.startsWith(`${root}/`)),
  );
}

function createDurableTestDataRoot() {
  const candidates = [REPO_ROOT, join(homedir(), ".cache", "rea-studio-tests")];
  for (const base of candidates) {
    try {
      mkdirSync(base, { recursive: true, mode: 0o700 });
      if (!isEphemeralTmpLocation(base)) {
        return mkdtempSync(join(base, ".rea-pilot-data-"));
      }
    } catch {
      // try next candidate
    }
  }
  return mkdtempSync(join(REPO_ROOT, ".rea-pilot-data-"));
}

async function allocateFreePort() {
  return new Promise((resolvePromise, rejectPromise) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      s.close((err) => (err ? rejectPromise(err) : resolvePromise(port)));
    });
    s.on("error", rejectPromise);
  });
}

async function startStudioServer({ dataDir, runtimeDir, extraEnv = {} } = {}) {
  const port = await allocateFreePort();
  const ownedDataDir = dataDir || createDurableTestDataRoot();
  const ownedRuntimeDir = runtimeDir || mkdtempSync(join(tmpdir(), "rea-pilot-rt-"));

  const env = {
    ...process.env,
    HOST: "127.0.0.1",
    PORT: String(port),
    REA_STUDIO_DATA_DIR: ownedDataDir,
    REA_STUDIO_RUNTIME_DIR: ownedRuntimeDir,
    ...extraEnv,
  };
  for (const [k, v] of Object.entries(extraEnv)) {
    if (v === undefined || v === null) delete env[k];
  }

  const proc = spawn(process.execPath, ["studio/server/index.mjs"], {
    cwd: REPO_ROOT,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let logs = "";
  await new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      rejectPromise(new Error(`Studio startup timeout:\n${logs}`));
    }, 20_000);

    const onChunk = (chunk) => {
      logs += chunk.toString("utf8");
      if (logs.includes("REA Cloud Studio listening on")) {
        clearTimeout(timer);
        resolvePromise();
      }
    };
    proc.stdout.on("data", onChunk);
    proc.stderr.on("data", onChunk);
    proc.once("exit", (code) => {
      clearTimeout(timer);
      rejectPromise(new Error(`Studio exited early (${code}):\n${logs}`));
    });
  });

  return {
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    dataDir: ownedDataDir,
    runtimeDir: ownedRuntimeDir,
    async stop({ keepDirs = false } = {}) {
      if (proc.exitCode === null) {
        proc.kill("SIGTERM");
        await new Promise((r) => proc.once("exit", r));
      }
      if (!keepDirs) {
        rmSync(ownedDataDir, { recursive: true, force: true });
        rmSync(ownedRuntimeDir, { recursive: true, force: true });
      }
    },
  };
}

function createPilotBrowserClient(baseUrl) {
  let cookiePair = "";
  let csrfToken = "";
  let apiKey = "";

  return {
    getCookie: () => cookiePair,
    getCsrf: () => csrfToken,
    getApiKey: () => apiKey,
    async request(path, options = {}) {
      const method = String(options.method || "GET").toUpperCase();
      const headers = {
        origin: baseUrl,
        ...(cookiePair ? { cookie: cookiePair } : {}),
        ...(method !== "GET" && method !== "HEAD" && csrfToken ? { "x-csrf-token": csrfToken } : {}),
        ...(options.headers || {}),
      };
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: options.body,
      });
      const setCookie = res.headers.get("set-cookie");
      if (setCookie) {
        const first = setCookie.split(";")[0];
        cookiePair = first.endsWith("=") ? "" : first;
      }
      const ctype = res.headers.get("content-type") || "";
      let body = null;
      if (ctype.includes("application/json")) {
        body = await res.json();
        if (typeof body?.csrf_token === "string" && body.csrf_token) {
          csrfToken = body.csrf_token;
        }
        if (body?.starter_api_key?.secret_token) {
          apiKey = body.starter_api_key.secret_token;
        }
      } else {
        body = Buffer.from(await res.arrayBuffer());
      }
      return { status: res.status, headers: res.headers, setCookie, body };
    },
  };
}

/**
 * Builds a PKZIP archive with bit 3 (0x0008 Data Descriptor + 0x08074b50 signature),
 * matching macOS Finder `ditto -c -k`, Java `ZipOutputStream`, and `archiver`.
 */
function buildDataDescriptorZipBuffer(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const cleanPath = entry.path.replace(/\\/g, "/").replace(/^\/+/, "");
    const nameBytes = Buffer.from(cleanPath, "utf8");
    const rawData = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(String(entry.data), "utf8");
    const comp = deflateRawSync(rawData, { level: 6 });
    const sum = crc32(rawData);

    // Local File Header with bit 3 (0x0008) + UTF-8 bit 11 (0x0800), zeroed sizes/CRC
    const lfh = Buffer.alloc(30 + nameBytes.length);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0x0808, 6);
    lfh.writeUInt16LE(8, 8);
    lfh.writeUInt32LE(0, 14);
    lfh.writeUInt32LE(0, 18);
    lfh.writeUInt32LE(0, 22);
    lfh.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(lfh, 30);

    // 16-byte Data Descriptor immediately following compressed payload
    const dd = Buffer.alloc(16);
    dd.writeUInt32LE(0x08074b50, 0);
    dd.writeUInt32LE(sum, 4);
    dd.writeUInt32LE(comp.length, 8);
    dd.writeUInt32LE(rawData.length, 12);

    // Central Directory Header with authoritative CRC-32 and sizes
    const cdh = Buffer.alloc(46 + nameBytes.length);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(0x0314, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0x0808, 8);
    cdh.writeUInt16LE(8, 10);
    cdh.writeUInt32LE(sum, 16);
    cdh.writeUInt32LE(comp.length, 20);
    cdh.writeUInt32LE(rawData.length, 24);
    cdh.writeUInt16LE(nameBytes.length, 28);
    cdh.writeUInt32LE(offset, 42);
    nameBytes.copy(cdh, 46);

    localParts.push(lfh, comp, dd);
    centralParts.push(cdh);
    offset += lfh.length + comp.length + dd.length;
  }

  const cdBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

/**
 * Raw HTTP wire helper so forbidden Fetch headers (`Host`, `Sec-Fetch-Site`)
 * are transmitted verbatim over TCP instead of stripped by Undici.
 */
function rawHttpJson(baseUrl, path, { method = "POST", headers = {}, bodyObj = null } = {}) {
  const u = new URL(path, baseUrl);
  const payload = bodyObj !== null ? Buffer.from(JSON.stringify(bodyObj), "utf8") : Buffer.alloc(0);
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest(
      {
        hostname: u.hostname,
        port: Number(u.port),
        path: u.pathname + u.search,
        method,
        headers: {
          "content-type": "application/json",
          "content-length": String(payload.length),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body = null;
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
          const rawSetCookie = res.headers["set-cookie"];
          const setCookie = Array.isArray(rawSetCookie) ? rawSetCookie.join("; ") : rawSetCookie || "";
          resolvePromise({ status: res.statusCode, headers: res.headers, setCookie, body });
        });
      },
    );
    req.on("error", rejectPromise);
    if (payload.length > 0) req.write(payload);
    req.end();
  });
}

/**
 * Builds an authentic Electron `.asar` archive via `@electron/asar` (including SHA-256 integrity blocks).
 */
async function buildRealAsarBuffer(filesMap) {
  const tmpRoot = mkdtempSync(join(tmpdir(), "rea-pilot-asar-"));
  const srcDir = join(tmpRoot, "src");
  const outAsar = join(tmpRoot, "app.asar");
  try {
    mkdirSync(srcDir, { recursive: true });
    for (const [relPath, content] of Object.entries(filesMap)) {
      const target = join(srcDir, relPath);
      mkdirSync(resolve(target, ".."), { recursive: true });
      writeFileSync(target, content);
    }
    await createAsarPackage(srcDir, outAsar);
    return readFileSync(outAsar);
  } finally {
    rmSync(tmpRoot, { recursive: true, force: true });
  }
}

test("AppScope X-Ray $49 Paid Pilot Validation Suite", async (t) => {
  // -------------------------------------------------------------------------
  // 1. Cookie, Localhost HTTP & Embedded Dev Preview Iframe Security Matrix
  // -------------------------------------------------------------------------
  await t.test("1. Preserves strict production cookies while supporting E2B preview iframes and HTTP loopback dev mode", async () => {
    const devSrv = await startStudioServer();
    try {
      // 1a. Default loopback keeps HttpOnly; Secure; SameSite=Lax
      const localReg = await rawHttpJson(devSrv.baseUrl, "/api/auth/register", {
        headers: { origin: devSrv.baseUrl },
        bodyObj: { org_name: "LocalDev", email: "local@pilot.test", password: "pilot-password-123" },
      });
      assert.equal(localReg.status, 200);
      assert.ok(localReg.setCookie.includes("HttpOnly"));
      assert.ok(localReg.setCookie.includes("Secure"));
      assert.ok(localReg.setCookie.includes("SameSite=Lax"));

      // 1b. Verified *.e2b.app dev preview iframe (Sec-Fetch-Site: cross-site + matching E2B Origin) succeeds
      const e2bHost = "3000-pilotpreview123.e2b.app";
      const e2bOrigin = `https://${e2bHost}`;
      const e2bReg = await rawHttpJson(devSrv.baseUrl, "/api/auth/register", {
        headers: {
          host: e2bHost,
          origin: e2bOrigin,
          "sec-fetch-site": "cross-site",
        },
        bodyObj: { org_name: "E2BIframe", email: "e2b@pilot.test", password: "pilot-password-123" },
      });
      assert.equal(e2bReg.status, 200);
      assert.ok(e2bReg.setCookie.includes("SameSite=None"));
      assert.ok(e2bReg.setCookie.includes("Secure"));
      assert.ok(e2bReg.setCookie.includes("Partitioned"));

      // Follow-up state-changing scan inside E2B cross-site iframe using the Partitioned cookie + CSRF succeeds!
      const e2bCookiePair = e2bReg.setCookie.split(";")[0];
      const e2bScan = await rawHttpJson(devSrv.baseUrl, "/api/xray/scan", {
        headers: {
          host: e2bHost,
          origin: e2bOrigin,
          "sec-fetch-site": "cross-site",
          cookie: e2bCookiePair,
          "x-csrf-token": e2bReg.body.csrf_token,
        },
        bodyObj: { sample_id: "acme-desktop-v1" },
      });
      assert.equal(e2bScan.status, 200);
      assert.equal(e2bScan.body.ok, true);

      // 1c. Forged third-party Origin against *.e2b.app host is STILL blocked (403 cross_origin_forbidden)
      const forgedE2b = await rawHttpJson(devSrv.baseUrl, "/api/auth/register", {
        headers: {
          host: e2bHost,
          origin: "https://evil-attacker.example",
          "sec-fetch-site": "cross-site",
        },
        bodyObj: { org_name: "Attacker", email: "evil@pilot.test", password: "pilot-password-123" },
      });
      assert.equal(forgedE2b.status, 403);
      assert.equal(forgedE2b.body?.error?.code, "cross_origin_forbidden");
    } finally {
      await devSrv.stop();
    }

    // 1d. Production mode NEVER issues SameSite=None, NEVER trusts *.e2b.app Host, and ignores REA_INSECURE_HTTP_DEV_COOKIES
    const prodSrv = await startStudioServer({
      extraEnv: {
        NODE_ENV: "production",
        PUBLIC_BASE_URL: "https://studio.rea.security",
        REA_INSECURE_HTTP_DEV_COOKIES: "true",
      },
    });
    try {
      const prodE2bAttempt = await rawHttpJson(prodSrv.baseUrl, "/api/auth/register", {
        headers: {
          host: "3000-pilotpreview123.e2b.app",
          origin: "https://3000-pilotpreview123.e2b.app",
          "sec-fetch-site": "cross-site",
        },
        bodyObj: { org_name: "ProdBypass", email: "bypass@pilot.test", password: "pilot-password-123" },
      });
      assert.equal(prodE2bAttempt.status, 403, "Production must reject untrusted e2b.app origin/host");

      const prodValidReg = await rawHttpJson(prodSrv.baseUrl, "/api/auth/register", {
        headers: {
          origin: "https://studio.rea.security",
        },
        bodyObj: { org_name: "ProdTenant", email: "prod@pilot.test", password: "pilot-password-123" },
      });
      assert.equal(prodValidReg.status, 200);
      assert.ok(prodValidReg.setCookie.includes("HttpOnly"));
      assert.ok(prodValidReg.setCookie.includes("Secure"), "Production must keep Secure cookie even if REA_INSECURE_HTTP_DEV_COOKIES=true");
      assert.ok(prodValidReg.setCookie.includes("SameSite=Lax"), "Production must keep SameSite=Lax");
      assert.equal(prodValidReg.setCookie.includes("SameSite=None"), false);
    } finally {
      await prodSrv.stop();
    }
  });

  // -------------------------------------------------------------------------
  // 2. Customer .zip Uploads (Nested GitHub Folder, macOS __MACOSX/._*.js, PKZIP 0x0008 Data Descriptor)
  // -------------------------------------------------------------------------
  await t.test("2. Unwraps nested GitHub/macOS .zip archives, scrubs AppleDouble metadata, and supports PKZIP 0x0008 data descriptors", async () => {
    const srv = await startStudioServer({ extraEnv: { ALLOW_SANDBOX_BILLING: "true" } });
    try {
      const client = createPilotBrowserClient(srv.baseUrl);
      const reg = await client.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org_name: "ZipPilot", email: "zip@pilot.test", password: "pilot-password-123" }),
      });
      assert.equal(reg.status, 200);

      // Provision $49 Indie plan (50 scans/month) in sandbox
      const upg = await client.request("/api/billing/confirm-sandbox", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan_id: "indie" }),
      });
      assert.equal(upg.status, 200);
      assert.equal(upg.body.tenant.plan_id, "indie");
      assert.equal(upg.body.tenant.usage.scan_limit, 50);

      // Baseline scan of acme-desktop-v1 directory
      const baseline = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "acme-desktop-v1" }),
      });
      assert.equal(baseline.status, 200);
      const findingIds = baseline.body.posture.findings.map((f) => f.id);
      assert.ok(findingIds.includes("REA-EL-001"), "Must detect child_process + missing senderFrame");
      assert.ok(findingIds.includes("REA-EL-003"), "Must detect sandbox: false on BrowserWindow");
      assert.ok(findingIds.includes("REA-EL-005"), "Must detect unpaired IPC channel");
      assert.ok(findingIds.includes("REA-EL-006"), "Must detect native .node addon");

      // Build customer macOS Finder + GitHub nested archive WITH PKZIP 0x0008 data descriptors + __MACOSX/._main.js!
      const v1SampleDir = join(srv.runtimeDir, "samples", "acme-desktop-v1");
      const macFinderZip = buildDataDescriptorZipBuffer([
        { path: "acme-desktop-v1-main/package.json", data: readFileSync(join(v1SampleDir, "package.json")) },
        { path: "acme-desktop-v1-main/main.js", data: readFileSync(join(v1SampleDir, "main.js")) },
        { path: "acme-desktop-v1-main/nativeBridge.js", data: readFileSync(join(v1SampleDir, "nativeBridge.js")) },
        { path: "acme-desktop-v1-main/addons/vault_cipher.node", data: readFileSync(join(v1SampleDir, "addons", "vault_cipher.node")) },
        { path: "acme-desktop-v1-main/preload.js", data: readFileSync(join(v1SampleDir, "preload.js")) },
        { path: "acme-desktop-v1-main/renderer.js", data: readFileSync(join(v1SampleDir, "renderer.js")) },
        { path: "acme-desktop-v1-main/index.html", data: readFileSync(join(v1SampleDir, "index.html")) },
        { path: "__MACOSX/acme-desktop-v1-main/._main.js", data: Buffer.from([0x00, 0x05, 0x16, 0x07, 0xff, 0xfe, 0x80, 0x99]) },
        { path: "acme-desktop-v1-main/._preload.js", data: Buffer.from([0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00]) },
        { path: "acme-desktop-v1-main/.DS_Store", data: Buffer.from([0x00, 0x00, 0x00, 0x01]) },
      ]);

      const upRes = await client.request("/api/upload", {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-filename": "acme-desktop-v1-main.zip",
        },
        body: macFinderZip,
      });
      assert.equal(upRes.status, 200);

      const zipScan = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upRes.body.saved_path }),
      });
      assert.equal(zipScan.status, 200);
      assert.equal(zipScan.body.statistics.invalid_utf8_files, 0, "AppleDouble ._*.js clutter must not pollute UTF-8 inventory");
      assert.equal(zipScan.body.root_artifact_sha256, baseline.body.root_artifact_sha256, "Unwrapped archive root SHA-256 must match direct directory scan");
      assert.equal(zipScan.body.posture.score, baseline.body.posture.score);
      assert.deepEqual(
        zipScan.body.posture.findings.map((f) => f.id),
        findingIds,
      );
    } finally {
      await srv.stop();
    }
  });

  // -------------------------------------------------------------------------
  // 3. Electron BrowserWindow webPreferences Detection & .asar Bundle Workflow
  // -------------------------------------------------------------------------
  await t.test("3. Detects nodeIntegration/contextIsolation/sandbox/webSecurity on IPC-less Electron apps and scans uploaded .asar bundles", async () => {
    const [{ parseEvidence, evidenceSemanticContent }, { digestCanonicalValue }] = await Promise.all([
      import(join(REPO_ROOT, "dist/domain/evidence.js")),
      import(join(REPO_ROOT, "dist/domain/canonicalDigest.js")),
    ]);

    const srv = await startStudioServer();
    try {
      const client = createPilotBrowserClient(srv.baseUrl);
      await client.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org_name: "AsarPilot", email: "asar@pilot.test", password: "pilot-password-123" }),
      });

      // First verify IPC-less insecure Electron app (previously a false-negative 100/100 APPROVED!)
      const ipcLessZip = buildZipBuffer([
        { path: "package.json", data: JSON.stringify({ name: "ipc-less-insecure", version: "1.0.0", main: "main.js" }) },
        {
          path: "main.js",
          data: `
            const { app, BrowserWindow } = require("electron");
            app.whenReady().then(() => {
              new BrowserWindow({
                webPreferences: {
                  nodeIntegration: true,
                  contextIsolation: false,
                  sandbox: false,
                  webSecurity: false
                }
              });
            });
          `,
        },
      ]);
      const upIpcLess = await client.request("/api/upload", {
        method: "POST",
        headers: { "content-type": "application/octet-stream", "x-filename": "ipc-less-insecure.zip" },
        body: ipcLessZip,
      });
      assert.equal(upIpcLess.status, 200);
      const scanIpcLess = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upIpcLess.body.saved_path }),
      });
      assert.equal(scanIpcLess.status, 200);
      assert.equal(scanIpcLess.body.posture.release_gate, "BLOCKED");
      assert.equal(scanIpcLess.body.posture.score, 30);
      assert.equal(scanIpcLess.body.posture.grade, "F");

      // Build authentic Electron .asar archive with insecure webPreferences and IPC RCE chain
      const asarBuf = await buildRealAsarBuffer({
        "package.json": JSON.stringify({ name: "customer-desktop", version: "2.1.0", main: "main.js" }),
        "main.js": `
          const { app, BrowserWindow, ipcMain } = require("electron");
          const { exec } = require("node:child_process");
          const path = require("node:path");
          ipcMain.handle("sys:exec", (_ev, cmd) => exec(cmd));
          app.whenReady().then(() => {
            new BrowserWindow({
              webPreferences: {
                preload: path.join(__dirname, "preload.js"),
                nodeIntegration: true,
                contextIsolation: false,
                sandbox: false,
                webSecurity: false
              }
            });
          });
        `,
        "preload.js": `
          const { contextBridge, ipcRenderer } = require("electron");
          contextBridge.exposeInMainWorld("deskApi", {
            execCmd: (cmd) => ipcRenderer.invoke("sys:exec", cmd)
          });
        `,
      });

      const upAsar = await client.request("/api/upload", {
        method: "POST",
        headers: { "content-type": "application/octet-stream", "x-filename": "app.asar" },
        body: asarBuf,
      });
      assert.equal(upAsar.status, 200);

      const scanAsar = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upAsar.body.saved_path }),
      });
      assert.equal(scanAsar.status, 200);
      assert.equal(scanAsar.body.posture.release_gate, "BLOCKED");
      assert.equal(scanAsar.body.posture.extracted.sandbox_disabled, true);
      assert.equal(scanAsar.body.posture.extracted.node_integration_enabled, true);
      assert.equal(scanAsar.body.posture.extracted.context_isolation_disabled, true);
      assert.equal(scanAsar.body.posture.extracted.web_security_disabled, true);

      const asarFindingIds = scanAsar.body.posture.findings.map((f) => f.id);
      for (const expectedId of ["REA-EL-001", "REA-EL-003", "REA-EL-004", "REA-EL-007"]) {
        assert.ok(asarFindingIds.includes(expectedId), `Expected finding ${expectedId} in ${asarFindingIds}`);
      }

      // Export both Markdown Audit Dossier (.md) and Cryptographic Evidence (.evidence.json)
      const evId = scanAsar.body.evidence_id;
      const mdRes = await client.request(`/api/evidence/${evId}/report?format=md`);
      assert.equal(mdRes.status, 200);
      const mdText = mdRes.body.toString("utf8");
      assert.ok(mdText.includes("# REA Cloud Studio — Cryptographic Audit Dossier"));
      assert.ok(mdText.includes(evId));
      assert.ok(mdText.includes("REA-EL-004"));
      assert.ok(mdText.includes("REA-EL-007"));
      assert.equal(mdText.includes(srv.runtimeDir), false, "Markdown report must never leak host runtimeDir");

      const jsonRes = await client.request(`/api/evidence/${evId}/report?format=json`);
      assert.equal(jsonRes.status, 200);
      const exportedObj = jsonRes.body;
      const recomputedId = `ev_${digestCanonicalValue(evidenceSemanticContent(exportedObj), "Evidence")}`;
      assert.equal(recomputedId, evId, "Exported .evidence.json canonical digest must match evidence_id");
      const parsed = parseEvidence(exportedObj);
      assert.equal(parsed.evidence_id, evId, "Exported .evidence.json must pass REA parseEvidence schema validation");
    } finally {
      await srv.stop();
    }
  });

  // -------------------------------------------------------------------------
  // 4. Durable SQLite Evidence Persistence Across Restart, Backup/Restore & Tamper Detection
  // -------------------------------------------------------------------------
  await t.test("4. Persists tenant-isolated Evidence & reports across server restarts and VACUUM INTO backups while rejecting tampered rows", async () => {
    const sharedDataDir = createDurableTestDataRoot();
    const sharedRuntimeDir = mkdtempSync(join(tmpdir(), "rea-persist-rt-"));
    const backupDir = mkdtempSync(join(tmpdir(), "rea-persist-bak-"));
    const restoredDataDir = createDurableTestDataRoot();

    let srv = await startStudioServer({ dataDir: sharedDataDir, runtimeDir: sharedRuntimeDir });
    let clientA;
    let clientB;
    let evIdA;
    let preRestartMd;

    try {
      clientA = createPilotBrowserClient(srv.baseUrl);
      clientB = createPilotBrowserClient(srv.baseUrl);

      await clientA.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org_name: "PersistAlpha", email: "alpha@persist.test", password: "pilot-password-123" }),
      });
      await clientB.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org_name: "PersistBravo", email: "bravo@persist.test", password: "pilot-password-123" }),
      });

      const scanA = await clientA.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sample_id: "acme-desktop-v1" }),
      });
      assert.equal(scanA.status, 200);
      evIdA = scanA.body.evidence_id;
      preRestartMd = (await clientA.request(`/api/evidence/${evIdA}/report?format=md`)).body.toString("utf8");

      // Stop server completely (wiping all in-memory Maps)
      await srv.stop({ keepDirs: true });

      // Hot-backup SQLite DB via VACUUM INTO and restore to a separate durable data directory
      const backupFile = join(backupDir, "pilot-backup.sqlite");
      backupSqliteDatabase(join(sharedDataDir, "studio.sqlite"), backupFile);
      restoreSqliteDatabase(backupFile, join(restoredDataDir, "studio.sqlite"));

      // Restart server on the restored SQLite database!
      srv = await startStudioServer({ dataDir: restoredDataDir, runtimeDir: sharedRuntimeDir });
      const clientARestarted = createPilotBrowserClient(srv.baseUrl);
      const clientBRestarted = createPilotBrowserClient(srv.baseUrl);

      const loginA = await clientARestarted.request("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alpha@persist.test", password: "pilot-password-123" }),
      });
      assert.equal(loginA.status, 200);

      const loginB = await clientBRestarted.request("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "bravo@persist.test", password: "pilot-password-123" }),
      });
      assert.equal(loginB.status, 200);

      // Tenant A's Evidence list, Markdown dossier, JSON envelope, Feature Trace, and Version Compare all work on cold boot!
      const listA = await clientARestarted.request("/api/evidence");
      assert.equal(listA.status, 200);
      assert.equal(listA.body.records.length, 1);
      assert.equal(listA.body.records[0].evidence_id, evIdA);
      assert.equal(listA.body.records[0].score, scanA.body.posture.score);

      const postRestartMd = await clientARestarted.request(`/api/evidence/${evIdA}/report?format=md`);
      assert.equal(postRestartMd.status, 200);
      assert.equal(postRestartMd.body.toString("utf8"), preRestartMd);

      const postRestartJson = await clientARestarted.request(`/api/evidence/${evIdA}/report?format=json`);
      assert.equal(postRestartJson.status, 200);

      const postRestartTrace = await clientARestarted.request("/api/xray/trace", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ evidence_id: evIdA, seed_kind: "channel", seed_value: "shell:open-diagnostic" }),
      });
      assert.equal(postRestartTrace.status, 200);
      assert.equal(postRestartTrace.body.ok, true);

      const postRestartCompare = await clientARestarted.request("/api/xray/compare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ left: evIdA, right: "acme-desktop-v2" }),
      });
      assert.equal(postRestartCompare.status, 200);
      assert.equal(postRestartCompare.body.ok, true);

      // Tenant B remains strictly isolated after cold-boot hydration (0 records, 404 on Tenant A's evidence_id)
      const listB = await clientBRestarted.request("/api/evidence");
      assert.equal(listB.body.records.length, 0);
      assert.equal((await clientBRestarted.request(`/api/evidence/${evIdA}`)).status, 404);
      assert.equal((await clientBRestarted.request(`/api/evidence/${evIdA}/report?format=md`)).status, 404);

      // Stop server, tamper 1 field in SQLite evidence_json, restart, and prove fail-closed tamper rejection (404)!
      await srv.stop({ keepDirs: true });
      const rawDb = new DatabaseSync(join(restoredDataDir, "studio.sqlite"));
      try {
        const row = rawDb.prepare("SELECT evidence_json FROM evidence_records WHERE evidence_id = ?").get(evIdA);
        const mutated = row.evidence_json.replace('"observed"', '"tampered"');
        rawDb.prepare("UPDATE evidence_records SET evidence_json = ? WHERE evidence_id = ?").run(mutated, evIdA);
      } finally {
        rawDb.close();
      }

      srv = await startStudioServer({ dataDir: restoredDataDir, runtimeDir: sharedRuntimeDir });
      const clientATampered = createPilotBrowserClient(srv.baseUrl);
      await clientATampered.request("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alpha@persist.test", password: "pilot-password-123" }),
      });
      const tamperedFetch = await clientATampered.request(`/api/evidence/${evIdA}/report?format=json`);
      assert.equal(tamperedFetch.status, 404, "Tampered SQLite Evidence row must fail closed and never be served");
    } finally {
      await srv.stop({ keepDirs: true }).catch(() => {});
      rmSync(sharedDataDir, { recursive: true, force: true });
      rmSync(sharedRuntimeDir, { recursive: true, force: true });
      rmSync(backupDir, { recursive: true, force: true });
      rmSync(restoredDataDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------------------
  // 5. Corrupt Input Error Handling, Quota Refund, CLI Release Gate & Idle Worker Reaping
  // -------------------------------------------------------------------------
  await t.test("5. Refunds scan quota on corrupt .zip/.asar uploads, enforces shipgate-cli.mjs gate, and reaps idle JS worker processes", async () => {
    const srv = await startStudioServer();
    try {
      const client = createPilotBrowserClient(srv.baseUrl);
      const reg = await client.request("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org_name: "ErrorPilot", email: "err@pilot.test", password: "pilot-password-123" }),
      });
      assert.equal(reg.status, 200);
      assert.equal(reg.body.tenant.usage.scans_used, 0);

      // Corrupt .asar upload -> fails cleanly (422) AND refunds scan quota (scans_used remains 0)
      const upCorruptAsar = await client.request("/api/upload", {
        method: "POST",
        headers: { "content-type": "application/octet-stream", "x-filename": "corrupt.asar" },
        body: Buffer.from("not-a-valid-asar-pickle-header-at-all"),
      });
      assert.equal(upCorruptAsar.status, 200);
      const scanCorruptAsar = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upCorruptAsar.body.saved_path }),
      });
      assert.equal(scanCorruptAsar.status, 422);
      assert.equal(scanCorruptAsar.body.tenant.usage.scans_used, 0, "Failed .asar scan must refund quota");

      // Corrupt .zip upload -> fails cleanly (400) AND refunds scan quota + leaves zero unpacked-* dirs
      const upCorruptZip = await client.request("/api/upload", {
        method: "POST",
        headers: { "content-type": "application/octet-stream", "x-filename": "broken.zip" },
        body: Buffer.from("PK\x03\x04corrupt-truncated-zip-archive"),
      });
      assert.equal(upCorruptZip.status, 200);
      const scanCorruptZip = await client.request("/api/xray/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ saved_path: upCorruptZip.body.saved_path }),
      });
      assert.equal(scanCorruptZip.status, 400);

      const meAfterErrors = await client.request("/api/auth/me");
      assert.equal(meAfterErrors.body.tenant.usage.scans_used, 0, "Corrupt ZIP must leave scans_used === 0");
      const tenantUploadDir = join(srv.runtimeDir, "uploads", reg.body.tenant.id);
      const lingeringUnpacked = readdirSync(tenantUploadDir, { recursive: true }).filter((p) =>
        String(p).includes("unpacked-"),
      );
      assert.equal(lingeringUnpacked.length, 0, "Zero unpacked-* temp directories may linger after failure");

      // Headless shipgate-cli.mjs xray against vulnerable v1 (exit 1 BLOCKED + $GITHUB_STEP_SUMMARY) & hardened v2 (exit 0 APPROVED)
      const summaryFile = join(srv.runtimeDir, "gh-step-summary.md");
      writeFileSync(summaryFile, "");
      const v1Dir = join(srv.runtimeDir, "samples", "acme-desktop-v1");
      const v2Dir = join(srv.runtimeDir, "samples", "acme-desktop-v2");

      let blockedExitCode = 0;
      try {
        await execFileAsync(process.execPath, ["studio/ci/shipgate-cli.mjs", "xray", v1Dir], {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            REA_STUDIO_URL: srv.baseUrl,
            REA_API_KEY: client.getApiKey(),
            GITHUB_STEP_SUMMARY: summaryFile,
          },
        });
      } catch (err) {
        blockedExitCode = err.code;
      }
      assert.equal(blockedExitCode, 1, "shipgate-cli.mjs must exit 1 on BLOCKED vulnerable Electron release");
      const summaryMd = readFileSync(summaryFile, "utf8");
      assert.ok(summaryMd.includes("Cryptographic Audit Dossier"));
      assert.ok(summaryMd.includes("REA-EL-001"));

      const approvedCli = await execFileAsync(process.execPath, ["studio/ci/shipgate-cli.mjs", "xray", v2Dir], {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          REA_STUDIO_URL: srv.baseUrl,
          REA_API_KEY: client.getApiKey(),
        },
      });
      assert.ok(approvedCli.stdout.includes("[APPROVED]"));
    } finally {
      await srv.stop();
    }

    // Direct verification of deterministic idle JS analysis worker reaping
    const { ReaStudioEngine } = await import("../server/reaEngine.mjs");
    const workerRt = mkdtempSync(join(tmpdir(), "rea-worker-reap-"));
    const eng = new ReaStudioEngine(REPO_ROOT, workerRt, { sessionIdleTtlMs: 1000 });
    try {
      await eng.scanJavaScriptApplication(
        "ten_worker_reap",
        join(REPO_ROOT, "website/public/examples/notes-electron"),
        "notes-electron",
      );
      assert.equal(eng.tenantSessions.size, 1);
      // Age slot beyond TTL and reap
      const slot = eng.tenantSessions.get("ten_worker_reap");
      slot.lastActiveAt = Date.now() - 5000;
      const reaped = await eng.reapIdleTenantSessions();
      assert.equal(reaped, 1);
      assert.equal(eng.tenantSessions.size, 0, "Idle MCP + JavaScriptAnalysisWorker slot must be closed and removed");
    } finally {
      await eng.close();
      rmSync(workerRt, { recursive: true, force: true });
    }
  });
});
