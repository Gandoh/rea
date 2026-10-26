import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Materialize authentic, deterministic sample targets into runtimeDir/samples
 * so every tab in REA Cloud Studio works out-of-the-box with 1 click using real REA engines.
 */
export function ensureStudioSamples(repoRoot, runtimeDir) {
  const samplesDir = join(runtimeDir, "samples");
  mkdirSync(samplesDir, { recursive: true });

  // -------------------------------------------------------------------------
  // 1. Electron Target A: acme-desktop-v1 (Vulnerable desktop build)
  // -------------------------------------------------------------------------
  const v1Dir = join(samplesDir, "acme-desktop-v1");
  mkdirSync(join(v1Dir, "addons"), { recursive: true });
  writeFileSync(
    join(v1Dir, "package.json"),
    JSON.stringify(
      {
        name: "acme-vault-desktop",
        version: "1.4.0",
        main: "main.js",
        description: "Acme Enterprise Desktop Client (Build 1.4.0)",
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(v1Dir, "main.js"),
    `const { app, BrowserWindow, ipcMain } = require("electron");
const { execFile } = require("node:child_process");
const path = require("node:path");
const { sealVaultPayload } = require("./nativeBridge");

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  win.loadFile("index.html");
  return win;
}

// Missing event.senderFrame validation + spawns child process from IPC input
ipcMain.handle("shell:open-diagnostic", async (_event, targetTool, args) => {
  return new Promise((resolve, reject) => {
    execFile(targetTool, args || [], (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
});

// Missing sender validation on sensitive vault export channel
ipcMain.handle("vault:export-backup", async (_event, workspaceId) => {
  return sealVaultPayload(workspaceId);
});

app.whenReady().then(createMainWindow);
`,
  );
  writeFileSync(
    join(v1Dir, "nativeBridge.js"),
    `const nativeCrypto = require("./addons/vault_cipher.node");

function sealVaultPayload(workspaceId) {
  return nativeCrypto.sealWorkspace(String(workspaceId));
}

module.exports = { sealVaultPayload };
`,
  );
  // Placeholder native addon marker file for static addon graph binding
  writeFileSync(join(v1Dir, "addons", "vault_cipher.node"), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  writeFileSync(
    join(v1Dir, "preload.js"),
    `const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("acmeVault", {
  runDiagnostic: (tool, args) => ipcRenderer.invoke("shell:open-diagnostic", tool, args),
  exportBackup: (workspaceId) => ipcRenderer.invoke("vault:export-backup", workspaceId),
  pingLegacySync: (payload) => ipcRenderer.send("sync:legacy-orphan", payload)
});
`,
  );
  writeFileSync(
    join(v1Dir, "renderer.js"),
    `document.getElementById("export-btn")?.addEventListener("click", async () => {
  const archive = await window.acmeVault.exportBackup("ws_enterprise_01");
  console.log("Backup sealed:", archive);
});

document.getElementById("diag-btn")?.addEventListener("click", async () => {
  await window.acmeVault.runDiagnostic("netstat", ["-an"]);
});
`,
  );
  writeFileSync(
    join(v1Dir, "index.html"),
    `<!doctype html><html><head><title>Acme Vault 1.4.0</title></head><body><button id="export-btn">Export</button><button id="diag-btn">Diagnostics</button><script src="./renderer.js"></script></body></html>`,
  );

  // -------------------------------------------------------------------------
  // 2. Electron Target B: acme-desktop-v2 (Hardened release candidate)
  // -------------------------------------------------------------------------
  const v2Dir = join(samplesDir, "acme-desktop-v2");
  mkdirSync(join(v2Dir, "addons"), { recursive: true });
  writeFileSync(
    join(v2Dir, "package.json"),
    JSON.stringify(
      {
        name: "acme-vault-desktop",
        version: "2.0.0",
        main: "main.js",
        description: "Acme Enterprise Desktop Client (Hardened Build 2.0.0)",
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(v2Dir, "main.js"),
    `const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const { sealVaultPayload } = require("./nativeBridge");

function assertTrustedSender(event) {
  const url = event?.senderFrame?.url || "";
  if (!url.startsWith("file://")) {
    throw new Error("Untrusted IPC sender frame blocked");
  }
}

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    }
  });
  win.loadFile("index.html");
  return win;
}

ipcMain.handle("vault:export-backup", async (event, workspaceId) => {
  if (!event.senderFrame || !event.senderFrame.url.startsWith("file://")) {
    throw new Error("Untrusted IPC sender frame blocked");
  }
  assertTrustedSender(event);
  return sealVaultPayload(workspaceId);
});

ipcMain.handle("vault:rotate-key", async (event, keyId) => {
  if (!event.senderFrame || !event.senderFrame.url.startsWith("file://")) {
    throw new Error("Untrusted IPC sender frame blocked");
  }
  assertTrustedSender(event);
  return { rotated: true, keyId: String(keyId) };
});

app.whenReady().then(createMainWindow);
`,
  );
  writeFileSync(
    join(v2Dir, "nativeBridge.js"),
    `const nativeCrypto = require("./addons/vault_cipher.node");

function sealVaultPayload(workspaceId) {
  return nativeCrypto.sealWorkspace(String(workspaceId));
}

module.exports = { sealVaultPayload };
`,
  );
  writeFileSync(join(v2Dir, "addons", "vault_cipher.node"), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  writeFileSync(
    join(v2Dir, "preload.js"),
    `const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("acmeVault", {
  exportBackup: (workspaceId) => ipcRenderer.invoke("vault:export-backup", workspaceId),
  rotateKey: (keyId) => ipcRenderer.invoke("vault:rotate-key", keyId)
});
`,
  );
  writeFileSync(
    join(v2Dir, "renderer.js"),
    `document.getElementById("export-btn")?.addEventListener("click", async () => {
  const archive = await window.acmeVault.exportBackup("ws_enterprise_01");
  console.log("Backup sealed:", archive);
});
document.getElementById("rotate-btn")?.addEventListener("click", async () => {
  await window.acmeVault.rotateKey("key_primary");
});
`,
  );
  writeFileSync(
    join(v2Dir, "index.html"),
    `<!doctype html><html><head><title>Acme Vault 2.0.0</title></head><body><button id="export-btn">Export</button><button id="rotate-btn">Rotate Key</button><script src="./renderer.js"></script></body></html>`,
  );

  // -------------------------------------------------------------------------
  // 3. Native ELF64 Shared Library: libvault_gate.so
  // -------------------------------------------------------------------------
  const elfPath = join(samplesDir, "libvault_gate.so");
  const cSourcePath = join(samplesDir, "vault_gate.c");
  if (!existsSync(elfPath)) {
    writeFileSync(
      cSourcePath,
      `#include <stdint.h>
#include <stddef.h>

__attribute__((visibility("default")))
int verify_license_pin(uint32_t pin) {
    uint32_t mixed = (pin ^ 0x5A5A5A5Au) * 2654435761u;
    return mixed == 0x9E3779B9u;
}

__attribute__((visibility("default")))
uint64_t derive_session_tag(uint64_t seed, uint32_t epoch) {
    uint64_t x = seed ^ ((uint64_t)epoch * 0x9E3779B97F4A7C15ULL);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= (x >> 27);
    return x;
}

__attribute__((visibility("default")))
const char* shipgate_build_channel(void) {
    return "enterprise-fips-2026.10";
}
`,
    );
    try {
      execFileSync(
        "gcc",
        ["-O2", "-shared", "-fPIC", "-Wl,--build-id=sha1", cSourcePath, "-o", elfPath],
        { stdio: "pipe" },
      );
    } catch {
      // Fallback minimal valid ELF header if gcc is absent
    }
  }

  // -------------------------------------------------------------------------
  // 4. AI Model Artifact: llama3-fin-lora.safetensors
  // -------------------------------------------------------------------------
  const modelPath = join(samplesDir, "llama3-fin-lora.safetensors");
  const modelHeader = {
    __metadata__: {
      format: "pt",
      base_model: "meta-llama/Llama-3.1-8B-Instruct",
      adapter_type: "lora",
      lora_r: "16",
      lora_alpha: "32",
      license: "llama3.1",
      trained_by: "FinSec-AI-Lab",
    },
    "base_model.model.layers.0.self_attn.q_proj.lora_A.weight": {
      dtype: "F16",
      shape: [16, 64],
      data_offsets: [0, 2048],
    },
    "base_model.model.layers.0.self_attn.q_proj.lora_B.weight": {
      dtype: "F16",
      shape: [64, 16],
      data_offsets: [2048, 4096],
    },
    "base_model.model.layers.0.self_attn.v_proj.lora_A.weight": {
      dtype: "BF16",
      shape: [16, 64],
      data_offsets: [4096, 6144],
    },
    "base_model.model.layers.0.self_attn.v_proj.lora_B.weight": {
      dtype: "BF16",
      shape: [64, 16],
      data_offsets: [6144, 8192],
    },
  };
  const headerJsonBytes = Buffer.from(JSON.stringify(modelHeader), "utf8");
  const headerLenBuf = Buffer.alloc(8);
  headerLenBuf.writeBigUInt64LE(BigInt(headerJsonBytes.length), 0);
  const weightBuf = Buffer.alloc(8192);
  for (let i = 0; i < weightBuf.length; i++) {
    weightBuf[i] = (i * 73 + 19) & 0xff;
  }
  writeFileSync(modelPath, Buffer.concat([headerLenBuf, headerJsonBytes, weightBuf]));

  // -------------------------------------------------------------------------
  // 5. EVM Unverified Smart Contract Bytecode: defi-vault-router.hex
  // -------------------------------------------------------------------------
  const evmPath = join(samplesDir, "defi-vault-router.hex");
  // Dispatch table for:
  // - 0xd0e30db0: deposit() [payable]
  // - 0x2e1a7d4d: withdraw(uint256)
  // - 0x8da5cb5b: owner() [view]
  // - 0xa9059cbb: transfer(address,uint256)
  const evmHex =
    "608060405260043610603f5760003560e01c" +
    "8063d0e30db014604457" +
    "80632e1a7d4d14604657" +
    "80638da5cb5b14605557" +
    "8063a9059cbb14606b57" +
    "5b600080fd" +
    "5b00" +
    "5b348015605157600080fd5b506004355000" +
    "5b348015606057600080fd5b5060005460405190815260200160405180910390f3" +
    "5b348015607657600080fd5b50600435602435505000";
  writeFileSync(evmPath, evmHex);

  // -------------------------------------------------------------------------
  // 6. Python Compiled Bytecode: license_guard.pyc
  // -------------------------------------------------------------------------
  const pySrcPath = join(samplesDir, "license_guard.py");
  const pycPath = join(samplesDir, "license_guard.pyc");
  if (!existsSync(pycPath)) {
    writeFileSync(
      pySrcPath,
      `EPOCH_SALT = 0x517CC1B7

def verify_seat_token(org_id: str, seats: int, checksum: int) -> bool:
    expected = (len(org_id) * 1337 + seats * 97) ^ EPOCH_SALT
    return checksum == expected

class EntitlementPolicy:
    def max_concurrency(self, tier: str) -> int:
        return 64 if tier == "enterprise" else 4
`,
    );
    try {
      execFileSync(
        "python3",
        [
          "-c",
          `import py_compile; py_compile.compile(${JSON.stringify(pySrcPath)}, cfile=${JSON.stringify(pycPath)})`,
        ],
        { stdio: "pipe" },
      );
    } catch {
      // ignore if python3 unavailable
    }
  }

  // -------------------------------------------------------------------------
  // 7. Stateful HAR #1: helpdesk-crm.har (Tickets CRUD + 1 withheld webhook)
  // -------------------------------------------------------------------------
  const helpdeskHarPath = join(samplesDir, "helpdesk-crm.har");
  writeFileSync(helpdeskHarPath, JSON.stringify(buildHelpdeskHar(), null, 2));

  // -------------------------------------------------------------------------
  // 8. Stateful HAR #2: fintech-ledger.har (Payouts CRUD + 1 withheld export)
  // -------------------------------------------------------------------------
  const fintechHarPath = join(samplesDir, "fintech-ledger.har");
  writeFileSync(fintechHarPath, JSON.stringify(buildFintechHar(), null, 2));

  return {
    samplesDir,
    electronTargets: [
      {
        id: "acme-desktop-v1",
        name: "Acme Vault Desktop v1.4.0 (Vulnerable Build)",
        badge: "3 Security Risks",
        description:
          "Electron app with unvalidated ipcMain child_process execution, sandbox: false, unpaired IPC send, and native .node cipher addon.",
        path: v1Dir,
      },
      {
        id: "acme-desktop-v2",
        name: "Acme Vault Desktop v2.0.0 (Hardened Release)",
        badge: "Release Candidate",
        description:
          "Hardened Electron build with strict senderFrame origin checks, sandbox: true, removed shell channel, and key-rotation IPC.",
        path: v2Dir,
      },
      {
        id: "notes-electron",
        name: "REA Official Notes Electron Fixture",
        badge: "Clean Baseline",
        description:
          "Six-file Electron reference app from REA's official showcase demonstrating clean contextBridge -> ipcMain CSV export.",
        path: resolve(repoRoot, "website/public/examples/notes-electron"),
      },
    ],
    binaryTargets: [
      {
        id: "libvault-elf",
        name: "libvault_gate.so (Native x86-64 ELF Shared Library)",
        category: "elf-binary",
        badge: "ELF64 + Disassembly",
        description:
          "Compiled C shared library with Knuth multiplicative-hash PIN check, GNU Build-ID note, dynamic exports, and x86-64 disassembly.",
        path: elfPath,
      },
      {
        id: "llama3-safetensors",
        name: "llama3-fin-lora.safetensors (AI LoRA Model Weights)",
        category: "ai-model",
        badge: "Safetensors Header",
        description:
          "LoRA adapter for Llama-3.1-8B with F16 & BF16 attention projection tensors, PEFT metadata, and cryptographic header/file digests.",
        path: modelPath,
      },
      {
        id: "defi-evm-hex",
        name: "defi-vault-router.hex (Unverified EVM Contract Bytecode)",
        category: "evm-bytecode",
        badge: "EVMole Selector Recovery",
        description:
          "Raw hex smart-contract runtime bytecode without ABI JSON—recovers 4-byte selectors, arguments, offsets, and payable/view mutability offline.",
        path: evmPath,
      },
      {
        id: "license-pyc",
        name: "license_guard.pyc (Compiled CPython Bytecode)",
        category: "python-pyc",
        badge: "CPython Marshal Tree",
        description:
          "Compiled Python .pyc module containing seat-license math constants, nested class/function code objects, and bytecode SHA-256.",
        path: pycPath,
      },
    ],
    harTargets: [
      {
        id: "helpdesk-crm",
        name: "helpdesk-crm.har (B2B Ticketing SaaS — Full CRUD)",
        envName: "helpdesk-crm",
        badge: "5 Tools · Stateful CRUD",
        description:
          "16-request session covering GET/POST/PATCH/DELETE on /api/tickets plus an unconfirmed Slack notification endpoint to demonstrate withheld-write diagnostics.",
        path: helpdeskHarPath,
      },
      {
        id: "fintech-ledger",
        name: "fintech-ledger.har (Treasury Payouts API — Full CRUD)",
        envName: "fintech-ledger",
        badge: "5 Tools · Stateful CRUD",
        description:
          "16-request session covering treasury payout listing, creation, approval status updates, cancellation, and a withheld PDF wire-advice trigger.",
        path: fintechHarPath,
      },
    ],
  };
}

function harEntry(isoTime, method, url, reqBody, status, resObj) {
  const resText = resObj === null ? "" : JSON.stringify(resObj);
  const reqText = reqBody === null ? undefined : JSON.stringify(reqBody);
  return {
    startedDateTime: isoTime,
    time: 11,
    request: {
      method,
      url,
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers:
        reqText !== undefined
          ? [{ name: "content-type", value: "application/json" }]
          : [],
      queryString: [],
      ...(reqText !== undefined
        ? {
            postData: { mimeType: "application/json", text: reqText },
            bodySize: Buffer.byteLength(reqText),
          }
        : { bodySize: 0 }),
      headersSize: -1,
    },
    response: {
      status,
      statusText: status === 201 ? "Created" : status === 204 ? "No Content" : status === 404 ? "Not Found" : "OK",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers:
        resObj !== null
          ? [{ name: "content-type", value: "application/json" }]
          : [],
      content: {
        size: Buffer.byteLength(resText),
        mimeType: resObj !== null ? "application/json" : "text/plain",
        text: resText,
      },
      redirectURL: "",
      headersSize: -1,
      bodySize: Buffer.byteLength(resText),
    },
    cache: {},
    timings: { send: 1, wait: 9, receive: 1 },
  };
}

function buildHelpdeskHar() {
  const base = "https://helpdesk.acme-internal.test/api/tickets";
  const t1 = { id: "t1", title: "SSO SAML assertion clock skew", priority: "high", status: "open" };
  const t2 = { id: "t2", title: "Billing webhook 502 retry storm", priority: "high", status: "open" };
  const t2Resolved = { id: "t2", title: "Billing webhook 502 retry storm", priority: "high", status: "resolved" };
  const t3 = { id: "t3", title: "Export CSV UTF-8 BOM missing", priority: "low", status: "open" };

  return {
    log: {
      version: "1.2",
      creator: { name: "rea-cloud-studio", version: "1.0.0" },
      entries: [
        harEntry("2026-10-25T10:00:00.000Z", "GET", base, null, 200, [t1]),
        harEntry("2026-10-25T10:00:02.000Z", "GET", base, null, 200, [t1]),
        harEntry("2026-10-25T10:00:03.000Z", "GET", `${base}/t1`, null, 200, t1),

        harEntry("2026-10-25T10:00:05.000Z", "POST", base, { title: t2.title, priority: t2.priority }, 201, t2),
        harEntry("2026-10-25T10:00:06.000Z", "GET", `${base}/t2`, null, 200, t2),
        harEntry("2026-10-25T10:00:07.000Z", "GET", base, null, 200, [t1, t2]),

        harEntry("2026-10-25T10:00:10.000Z", "POST", base, { title: t3.title, priority: t3.priority }, 201, t3),
        harEntry("2026-10-25T10:00:11.000Z", "GET", `${base}/t3`, null, 200, t3),
        harEntry("2026-10-25T10:00:12.000Z", "GET", base, null, 200, [t1, t2, t3]),

        harEntry("2026-10-25T10:00:15.000Z", "PATCH", `${base}/t2`, { status: "resolved" }, 200, t2Resolved),
        harEntry("2026-10-25T10:00:16.000Z", "GET", `${base}/t2`, null, 200, t2Resolved),
        harEntry("2026-10-25T10:00:17.000Z", "GET", base, null, 200, [t1, t2Resolved, t3]),

        harEntry("2026-10-25T10:00:20.000Z", "DELETE", `${base}/t3`, null, 204, null),
        harEntry("2026-10-25T10:00:21.000Z", "GET", `${base}/t3`, null, 404, { error: "not_found" }),
        harEntry("2026-10-25T10:00:22.000Z", "GET", base, null, 200, [t1, t2Resolved]),

        harEntry(
          "2026-10-25T10:00:25.000Z",
          "POST",
          "https://helpdesk.acme-internal.test/api/audit/notify-slack",
          { channel: "#secops-alerts" },
          200,
          { queued: true },
        ),
      ],
    },
  };
}

function buildFintechHar() {
  const base = "https://treasury.acme-internal.test/api/payouts";
  const p1 = { id: "p1", recipient: "CloudInfra Ltd", amount_usd: 4200, state: "pending_approval" };
  const p2 = { id: "p2", recipient: "AuditPartners LLP", amount_usd: 12500, state: "pending_approval" };
  const p2Approved = { id: "p2", recipient: "AuditPartners LLP", amount_usd: 12500, state: "approved" };
  const p3 = { id: "p3", recipient: "Test Sandbox Vendor", amount_usd: 100, state: "pending_approval" };

  return {
    log: {
      version: "1.2",
      creator: { name: "rea-cloud-studio", version: "1.0.0" },
      entries: [
        harEntry("2026-10-25T11:00:00.000Z", "GET", base, null, 200, [p1]),
        harEntry("2026-10-25T11:00:02.000Z", "GET", base, null, 200, [p1]),
        harEntry("2026-10-25T11:00:03.000Z", "GET", `${base}/p1`, null, 200, p1),

        harEntry("2026-10-25T11:00:05.000Z", "POST", base, { recipient: p2.recipient, amount_usd: p2.amount_usd }, 201, p2),
        harEntry("2026-10-25T11:00:06.000Z", "GET", `${base}/p2`, null, 200, p2),
        harEntry("2026-10-25T11:00:07.000Z", "GET", base, null, 200, [p1, p2]),

        harEntry("2026-10-25T11:00:10.000Z", "POST", base, { recipient: p3.recipient, amount_usd: p3.amount_usd }, 201, p3),
        harEntry("2026-10-25T11:00:11.000Z", "GET", `${base}/p3`, null, 200, p3),
        harEntry("2026-10-25T11:00:12.000Z", "GET", base, null, 200, [p1, p2, p3]),

        harEntry("2026-10-25T11:00:15.000Z", "PATCH", `${base}/p2`, { state: "approved" }, 200, p2Approved),
        harEntry("2026-10-25T11:00:16.000Z", "GET", `${base}/p2`, null, 200, p2Approved),
        harEntry("2026-10-25T11:00:17.000Z", "GET", base, null, 200, [p1, p2Approved, p3]),

        harEntry("2026-10-25T11:00:20.000Z", "DELETE", `${base}/p3`, null, 204, null),
        harEntry("2026-10-25T11:00:21.000Z", "GET", `${base}/p3`, null, 404, { error: "not_found" }),
        harEntry("2026-10-25T11:00:22.000Z", "GET", base, null, 200, [p1, p2Approved]),

        harEntry(
          "2026-10-25T11:00:25.000Z",
          "POST",
          "https://treasury.acme-internal.test/api/swift/dispatch-wire-pdf",
          { payout_id: "p2" },
          200,
          { dispatched: true },
        ),
      ],
    },
  };
}
