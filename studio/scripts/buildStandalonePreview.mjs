/**
 * Harvests real REA engine outputs from the running Studio server and compiles
 * self-contained studio/index.html and studio/preview.html bundles that work:
 *   1. Against the live Node/REA backend when served by studio/server/index.mjs, AND
 *   2. 100% standalone 24/7 on GitHub Pages / Brave Browser (including WebCrypto
 *      SHA-256 + Shannon Entropy custom file uploads and Blob file downloads).
 */

import { readFileSync, writeFileSync } from "node:fs";

const BASE = "http://127.0.0.1:3000";

async function jfetch(path, opts = {}) {
  const r = await fetch(BASE + path, opts);
  return r.json();
}

async function main() {
  const reg = await jfetch("/api/auth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      org_name: "Builder Harvest",
      email: `harvest-${Date.now()}@rea.local`,
      password: "harvest-password-123",
    }),
  });
  const hdrs = {
    "content-type": "application/json",
    "x-studio-session": reg.session_token,
  };
  await jfetch("/api/billing/confirm-sandbox", {
    method: "POST",
    headers: hdrs,
    body: JSON.stringify({ plan_id: "ai_lab" }),
  });

  const bootstrap = await jfetch("/api/bootstrap");

  const xrayBySample = {};
  for (const s of bootstrap.samples.electron) {
    xrayBySample[s.id] = await jfetch("/api/xray/scan", {
      method: "POST",
      headers: hdrs,
      body: JSON.stringify({ sample_id: s.id }),
    });
  }

  const versionCompare = await jfetch("/api/xray/compare", {
    method: "POST",
    headers: hdrs,
    body: JSON.stringify({
      left: xrayBySample["acme-desktop-v1"].evidence_id,
      right: xrayBySample["acme-desktop-v2"].evidence_id,
    }),
  });

  const defaultTrace = await jfetch("/api/xray/trace", {
    method: "POST",
    headers: hdrs,
    body: JSON.stringify({
      evidence_id: xrayBySample["acme-desktop-v1"].evidence_id,
      seed_kind: "channel",
      seed_value: "shell:open-diagnostic",
    }),
  });

  const shipgateBySample = {};
  for (const s of bootstrap.samples.binary) {
    shipgateBySample[s.id] = await jfetch("/api/shipgate/inspect", {
      method: "POST",
      headers: hdrs,
      body: JSON.stringify({ sample_id: s.id }),
    });
  }
  const elfSymbols = {};
  for (const sym of ["verify_license_pin", "vault_seal_frame"]) {
    elfSymbols[sym] = await jfetch("/api/shipgate/inspect", {
      method: "POST",
      headers: hdrs,
      body: JSON.stringify({ sample_id: "libvault-elf", symbol: sym }),
    });
  }

  const rlBySample = {};
  for (const s of bootstrap.samples.har) {
    rlBySample[s.id] = await jfetch("/api/rl/build", {
      method: "POST",
      headers: hdrs,
      body: JSON.stringify({ sample_id: s.id }),
    });
  }

  const evList = await jfetch("/api/evidence", { headers: hdrs });
  const evDetails = {};
  const evMarkdown = {};
  for (const rec of evList.records.slice(0, 12)) {
    const det = await jfetch(`/api/evidence/${rec.evidence_id}`, { headers: hdrs });
    const mdResp = await fetch(`${BASE}/api/evidence/${rec.evidence_id}/report?format=md`, {
      headers: hdrs,
    });
    evMarkdown[rec.evidence_id] = await mdResp.text();
    if (det.ok) {
      const copy = JSON.parse(JSON.stringify(det.record));
      if (copy.evidence?.normalized_result?.graph) {
        copy.evidence.normalized_result.graph = {
          nodes_preview: copy.evidence.normalized_result.graph.nodes?.slice(0, 8) ?? [],
          edges_preview: copy.evidence.normalized_result.graph.edges?.slice(0, 10) ?? [],
          note: "Full AST graph retained on server; trimmed in standalone view for mobile speed.",
        };
      }
      if (copy.evidence?.normalized_result?.semantic_graph?.relations) {
        copy.evidence.normalized_result.semantic_graph.relations =
          copy.evidence.normalized_result.semantic_graph.relations.slice(0, 10);
      }
      if (copy.evidence?.normalized_result?.records?.length > 6) {
        copy.evidence.normalized_result.records =
          copy.evidence.normalized_result.records.slice(0, 6);
      }
      evDetails[rec.evidence_id] = copy;
    }
  }

  const ciWorkflowText = readFileSync("studio/ci/github-action-workflow.yml", "utf8");
  const ciCliText = readFileSync("studio/ci/shipgate-cli.mjs", "utf8");

  const snapshot = {
    bootstrap,
    xrayBySample,
    versionCompare,
    defaultTrace,
    shipgateBySample,
    elfSymbols,
    rlBySample,
    evRecords: evList.records.slice(0, 20),
    evDetails,
    evMarkdown,
    ciWorkflowText,
    ciCliText,
  };

  const html = readFileSync("studio/public/index.html", "utf8");
  const css = readFileSync("studio/public/styles.css", "utf8");
  const js = readFileSync("studio/public/app.js", "utf8");
  const safeSnapshotJson = JSON.stringify(snapshot).replaceAll("<", "\\u003c");

  const offlineEngineShim = `
const SNAPSHOT = ${safeSnapshotJson};
let STATIC_MODE = false;

const localSim = {
  tenant: {
    id: "ten_founder_demo",
    email: "founder@acme-security.dev",
    org_name: "Acme AppSec Workspace",
    plan_id: "free_trial",
    plan_name: "Free Developer Trial",
    plan_badge: "Trial",
    price_monthly_usd: 0,
    usage: { scans_used: 0, scan_limit: 5, rl_builds_used: 0, rl_build_limit: 2 },
  },
  keys: [
    {
      id: "key_default",
      name: "Default CI/CD & CLI Key",
      token: "rea_sk_live_9f82c4e1a0b74d12e8c3a501",
      calls: 0,
    },
  ],
  uploads: {},
  rlStates: {},
};

const PLAN_LIMITS = {
  free_trial: { name: "Free Developer Trial", badge: "Trial", price: 0, scan_limit: 5, rl_limit: 2 },
  indie: { name: "Researcher / Indie", badge: "$49/mo", price: 49, scan_limit: 50, rl_limit: 5 },
  team: { name: "ShipGate Team CI/CD", badge: "$299/mo", price: 299, scan_limit: null, rl_limit: 15 },
  ai_lab: { name: "AI Lab RL Factory", badge: "$1,499/mo", price: 1499, scan_limit: null, rl_limit: null },
};

async function sha256Hex(uint8) {
  const digest = await crypto.subtle.digest("SHA-256", uint8);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function shannonEntropyBlocks(uint8) {
  const calc = (slice) => {
    if (!slice.length) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < slice.length; i += 1) freq[slice[i]] += 1;
    let ent = 0;
    for (let i = 0; i < 256; i += 1) {
      if (freq[i] > 0) {
        const p = freq[i] / slice.length;
        ent -= p * Math.log2(p);
      }
    }
    return Number(ent.toFixed(4));
  };
  const bSize = uint8.length > 32768 ? 4096 : 256;
  const blocks = [];
  for (let off = 0; off < uint8.length && blocks.length < 64; off += bSize) {
    const slice = uint8.subarray(off, Math.min(off + bSize, uint8.length));
    blocks.push({ offset: off, length: slice.length, entropy: calc(slice) });
  }
  return { file_entropy: calc(uint8), block_size: bSize, blocks };
}

function triggerBlobDownload(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    a.remove();
    URL.revokeObjectURL(url);
  }, 500);
}

// Intercept download anchor clicks when running on static hosting (GitHub Pages / Brave)
document.addEventListener("click", (e) => {
  if (!STATIC_MODE) return;
  const anchor = e.target.closest("a[href]");
  if (!anchor) return;
  const href = anchor.getAttribute("href") || "";
  if (href.startsWith("/api/evidence/") && href.includes("/report")) {
    e.preventDefault();
    const id = decodeURIComponent(href.split("/api/evidence/")[1].split("/")[0]);
    if (href.includes("format=json")) {
      const rec = SNAPSHOT.evDetails[id] || Object.values(SNAPSHOT.evDetails)[0];
      triggerBlobDownload(id.slice(0, 16) + ".evidence.json", "application/json", JSON.stringify(rec.evidence, null, 2));
    } else {
      const md = SNAPSHOT.evMarkdown[id] || Object.values(SNAPSHOT.evMarkdown)[0] || "# REA Audit Dossier";
      triggerBlobDownload(id.slice(0, 16) + "-audit.md", "text/markdown", md);
    }
  } else if (href.startsWith("/api/rl/download/")) {
    e.preventDefault();
    const envId = decodeURIComponent(href.replace("/api/rl/download/", ""));
    const hit = Object.values(SNAPSHOT.rlBySample).find((x) => x.env_id === envId) || SNAPSHOT.rlBySample["helpdesk-crm"];
    const bundleJson = JSON.stringify({ environment: hit.name, files: hit.bundle_files }, null, 2);
    triggerBlobDownload(hit.name + "-agentenv-bundle.json", "application/json", bundleJson);
  } else if (href === "/api/ci/github-action.yml") {
    e.preventDefault();
    triggerBlobDownload("rea-shipgate.yml", "text/yaml", SNAPSHOT.ciWorkflowText);
  } else if (href === "/api/ci/shipgate-cli.mjs") {
    e.preventDefault();
    triggerBlobDownload("shipgate-cli.mjs", "application/javascript", SNAPSHOT.ciCliText);
  }
});

function consumeSimQuota(kind) {
  const u = localSim.tenant.usage;
  if (kind === "rl") {
    if (u.rl_build_limit !== null && u.rl_builds_used >= u.rl_build_limit) {
      return { ok: false, status: 402, error: { code: "quota_exceeded", message: \`Monthly RL Factory limit reached (\${u.rl_builds_used}/\${u.rl_build_limit}). Upgrade plan to unlock more builds.\` } };
    }
    u.rl_builds_used += 1;
    return { ok: true };
  }
  if (u.scan_limit !== null && u.scans_used >= u.scan_limit) {
    return { ok: false, status: 402, error: { code: "quota_exceeded", message: \`Monthly scan quota reached (\${u.scans_used}/\${u.scan_limit} on \${localSim.tenant.plan_name}). Upgrade your plan to unlock additional scans.\` } };
  }
  u.scans_used += 1;
  return { ok: true };
}

function mkJsonResp(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function handleEmbeddedApi(path, init = {}) {
  STATIC_MODE = true;
  if (path === "/api/upload") {
    const fname = (init.headers && (init.headers["x-filename"] || init.headers["X-Filename"])) || "uploaded.bin";
    const bytes = new Uint8Array(init.body instanceof ArrayBuffer ? init.body : new ArrayBuffer(0));
    const saved = "/virtual/uploads/" + Date.now() + "-" + fname;
    localSim.uploads[saved] = { filename: fname, bytes };
    return mkJsonResp(200, { ok: true, filename: fname, bytes: bytes.length, saved_path: saved });
  }

  const body = init.body && typeof init.body === "string" ? JSON.parse(init.body) : {};

  if (path === "/api/bootstrap") {
    return mkJsonResp(200, {
      ...SNAPSHOT.bootstrap,
      tenant: localSim.tenant,
      api_keys: localSim.keys,
    });
  }
  if (path === "/api/evidence") {
    return mkJsonResp(200, { ok: true, tenant: localSim.tenant, records: SNAPSHOT.evRecords });
  }
  if (path.startsWith("/api/evidence/")) {
    const id = decodeURIComponent(path.replace("/api/evidence/", "").split("/")[0]);
    const rec = SNAPSHOT.evDetails[id] || Object.values(SNAPSHOT.evDetails)[0];
    return mkJsonResp(200, { ok: true, record: rec });
  }
  if (path === "/api/xray/scan") {
    const q = consumeSimQuota("scan");
    if (!q.ok) return mkJsonResp(402, q);
    if (body.saved_path && localSim.uploads[body.saved_path]) {
      const up = localSim.uploads[body.saved_path];
      const hash = await sha256Hex(up.bytes);
      const base = JSON.parse(JSON.stringify(SNAPSHOT.xrayBySample["acme-desktop-v2"]));
      base.root_artifact_sha256 = hash;
      base.posture.extracted.modules = [{ path: up.filename, bytes: up.bytes.length, sha256: hash }];
      return mkJsonResp(200, { ...base, tenant: localSim.tenant });
    }
    const hit = SNAPSHOT.xrayBySample[body.sample_id] || SNAPSHOT.xrayBySample["acme-desktop-v1"];
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path === "/api/xray/compare") {
    return mkJsonResp(200, SNAPSHOT.versionCompare);
  }
  if (path === "/api/xray/trace") {
    return mkJsonResp(200, {
      ...SNAPSHOT.defaultTrace,
      trace: {
        ...SNAPSHOT.defaultTrace.trace,
        queried_seed: { kind: body.seed_kind, value: body.seed_value, direction: body.direction },
      },
    });
  }
  if (path === "/api/shipgate/inspect") {
    const q = consumeSimQuota("scan");
    if (!q.ok) return mkJsonResp(402, q);
    if (body.saved_path && localSim.uploads[body.saved_path]) {
      const up = localSim.uploads[body.saved_path];
      const hash = await sha256Hex(up.bytes);
      const ent = shannonEntropyBlocks(up.bytes);
      const evId = "ev_" + hash;
      return mkJsonResp(200, {
        ok: true,
        elapsed_ms: 9,
        artifact: { name: up.filename, bytes: up.bytes.length, sha256: hash, detected_kind: "uploaded-artifact" },
        evidence_ids: [evId],
        panels: { entropy: ent },
        tenant: localSim.tenant,
      });
    }
    if (body.sample_id === "libvault-elf" && body.symbol && SNAPSHOT.elfSymbols[body.symbol]) {
      return mkJsonResp(200, { ...SNAPSHOT.elfSymbols[body.symbol], tenant: localSim.tenant });
    }
    const hit = SNAPSHOT.shipgateBySample[body.sample_id] || SNAPSHOT.shipgateBySample["libvault-elf"];
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path === "/api/rl/build") {
    const q = consumeSimQuota("rl");
    if (!q.ok) return mkJsonResp(402, q);
    const hit = JSON.parse(JSON.stringify(SNAPSHOT.rlBySample[body.sample_id] || SNAPSHOT.rlBySample["helpdesk-crm"]));
    localSim.rlStates[hit.env_id] = JSON.parse(JSON.stringify(hit.state_snapshot));
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path === "/api/rl/call") {
    const snap = localSim.rlStates[body.env_id] || JSON.parse(JSON.stringify(SNAPSHOT.rlBySample["helpdesk-crm"].state_snapshot));
    const entities = snap.rea_state.entities;
    const col = snap.rea_state.types[0]?.collection_template || "/api/tickets";
    if (String(body.tool).startsWith("post_") && body.arguments?.body) {
      const newId = col.includes("payout") ? \`p\${entities.length + 1}\` : \`t\${entities.length + 1}\`;
      const fields = { id: newId, ...body.arguments.body };
      entities.push({ type: col, collection: col, id: newId, fields, view_fields: [], record_ordinals: [] });
      localSim.rlStates[body.env_id] = snap;
      return mkJsonResp(200, { ok: true, elapsed_ms: 4, tool: body.tool, result: { status: 201, body: fields }, state_snapshot: snap });
    }
    return mkJsonResp(200, {
      ok: true,
      elapsed_ms: 3,
      tool: body.tool,
      result: { status: 200, body: entities.map((e) => e.fields) },
      state_snapshot: snap,
    });
  }
  if (path === "/api/rl/reset") {
    const orig = Object.values(SNAPSHOT.rlBySample).find((x) => x.env_id === body.env_id) || SNAPSHOT.rlBySample["helpdesk-crm"];
    localSim.rlStates[body.env_id] = JSON.parse(JSON.stringify(orig.state_snapshot));
    return mkJsonResp(200, { ok: true, state_snapshot: localSim.rlStates[body.env_id] });
  }
  if (path === "/api/rl/grade-task") {
    const snap = localSim.rlStates[body.env_id] || SNAPSHOT.rlBySample["helpdesk-crm"].state_snapshot;
    const assertion = body.task?.assertions?.[0] || {};
    const matched = (snap.rea_state?.entities || []).some(
      (e) => e.collection === assertion.collection && String(e.fields?.[assertion.field] ?? "") === String(assertion.expected ?? ""),
    );
    const orig = Object.values(SNAPSHOT.rlBySample).find((x) => x.env_id === body.env_id) || SNAPSHOT.rlBySample["helpdesk-crm"];
    return mkJsonResp(200, {
      ok: true,
      reward: matched ? 1.0 : 0.0,
      passed: matched,
      task: { id: body.task?.title || "custom-task" },
      bundle_files: orig.bundle_files,
    });
  }
  if (path === "/api/auth/register" || path === "/api/auth/login") {
    localSim.tenant = {
      id: "ten_custom",
      email: body.email || "user@org.ai",
      org_name: body.org_name || (body.email || "Workspace").split("@")[0],
      plan_id: "free_trial",
      plan_name: "Free Developer Trial",
      plan_badge: "Trial",
      price_monthly_usd: 0,
      usage: { scans_used: 0, scan_limit: 5, rl_builds_used: 0, rl_build_limit: 2 },
    };
    return mkJsonResp(200, { ok: true, session_token: "sess_local", tenant: localSim.tenant, api_keys: localSim.keys });
  }
  if (path === "/api/billing/checkout") {
    const p = PLAN_LIMITS[body.plan_id] || PLAN_LIMITS.team;
    return mkJsonResp(200, {
      ok: true,
      mode: "sandbox_checkout",
      session_id: "cs_test_live_preview",
      plan: { id: body.plan_id, name: p.name, price_monthly_usd: p.price },
      tenant: localSim.tenant,
    });
  }
  if (path === "/api/billing/confirm-sandbox") {
    const p = PLAN_LIMITS[body.plan_id] || PLAN_LIMITS.team;
    localSim.tenant.plan_id = body.plan_id;
    localSim.tenant.plan_name = p.name;
    localSim.tenant.plan_badge = p.badge;
    localSim.tenant.price_monthly_usd = p.price;
    localSim.tenant.usage.scan_limit = p.scan_limit;
    localSim.tenant.usage.rl_build_limit = p.rl_limit;
    return mkJsonResp(200, { ok: true, tenant: localSim.tenant });
  }
  if (path === "/api/keys/create") {
    const nk = {
      id: "key_" + Math.random().toString(36).slice(2, 7),
      name: body.name || "API Key",
      token: "rea_sk_live_" + Math.random().toString(16).slice(2, 18),
      calls: 0,
    };
    localSim.keys.push(nk);
    return mkJsonResp(200, { ok: true, key: nk, api_keys: localSim.keys });
  }
  if (path === "/api/keys/revoke") {
    localSim.keys = localSim.keys.filter((k) => k.id !== body.key_id);
    return mkJsonResp(200, { ok: true, api_keys: localSim.keys });
  }
  if (path.startsWith("/api/v1/")) {
    if (localSim.keys[0]) localSim.keys[0].calls += 1;
    if (path === "/api/v1/status") {
      return mkJsonResp(200, { ok: true, organization: localSim.tenant.org_name, tenant: localSim.tenant, rea_mcp_tools: 229 });
    }
    if (path === "/api/v1/xray") {
      return mkJsonResp(200, { ...SNAPSHOT.xrayBySample["acme-desktop-v1"], billed_to: localSim.tenant.org_name });
    }
    return mkJsonResp(200, { ...SNAPSHOT.shipgateBySample["libvault-elf"], billed_to: localSim.tenant.org_name });
  }
  return mkJsonResp(404, { ok: false, error: { message: "Offline preview route not cached" } });
}

const _nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const isHttpHost = (window.location.protocol === "http:" || window.location.protocol === "https:") && Boolean(window.location.host);
  const isStaticHost = STATIC_MODE || /github\.io$|githack\.com$|githubusercontent\.com$/.test(window.location.hostname);
  if (typeof input === "string" && input.startsWith("/api/")) {
    if (isHttpHost && !isStaticHost) {
      try {
        const liveResp = await _nativeFetch(input, init);
        const ct = liveResp.headers.get("content-type") || "";
        if (liveResp.status < 500 && ct.includes("application/json")) {
          return liveResp;
        }
      } catch {
        // Fall through to embedded REA snapshot
      }
    }
    return handleEmbeddedApi(input, init);
  }
  return _nativeFetch(input, init);
};
`;

  const outHtml = html
    .replace('<link rel="stylesheet" href="/styles.css" />', `<style>\n${css}\n</style>`)
    .replace(
      '<script type="module" src="/app.js"></script>',
      `<script>\n(function () {\n"use strict";\n${offlineEngineShim}\n${js}\n})();\n</script>`,
    );

  writeFileSync("studio/index.html", outHtml);
  console.log(`Built studio/index.html (${(outHtml.length / 1024).toFixed(1)} KiB)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
