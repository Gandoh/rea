/**
 * Harvests real REA engine outputs from an ephemeral in-process Studio server
 * (with ALLOW_SANDBOX_BILLING=true during build only) and compiles studio/index.html:
 *   1. Against the live Node/REA backend when served by studio/server/index.mjs, AND
 *   2. Read-only static sample viewer when opened as a standalone file (explicitly
 *      refuses custom file uploads so arbitrary files are NEVER falsely certified).
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function startEphemeralServer() {
  const tempRoot = mkdtempSync(join(tmpdir(), "rea-preview-build-"));
  process.env.REA_STUDIO_NO_AUTO_LISTEN = "true";
  process.env.REA_STUDIO_RUNTIME_DIR = join(tempRoot, "runtime");
  process.env.REA_STUDIO_DATA_DIR = join(tempRoot, "data");
  process.env.ALLOW_SANDBOX_BILLING = "true";
  process.env.NODE_ENV = "development";

  const { server, engine, billing } = await import("../server/index.mjs");
  await engine.init();
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    engine,
    async close() {
      await new Promise((r) => server.close(r));
      await engine.close();
      billing.close();
      rmSync(tempRoot, { recursive: true, force: true });
    },
  };
}

async function main() {
  const ephemeral = process.env.REA_BUILD_URL ? null : await startEphemeralServer();
  const BASE = process.env.REA_BUILD_URL || ephemeral.baseUrl;

  try {
    let cookieJar = "";
    let csrfToken = "";

    const jfetch = async (path, opts = {}) => {
      const method = String(opts.method || "GET").toUpperCase();
      const headers = {
        origin: BASE,
        ...(cookieJar ? { cookie: cookieJar } : {}),
        ...(method !== "GET" && csrfToken ? { "x-csrf-token": csrfToken } : {}),
        ...(opts.headers || {}),
      };
      const r = await fetch(BASE + path, { ...opts, headers });
      const sc = r.headers.get("set-cookie");
      if (sc) {
        cookieJar = sc.split(";")[0];
      }
      const data = await r.json();
      if (data?.csrf_token) csrfToken = data.csrf_token;
      return data;
    };

    const reg = await jfetch("/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        org_name: "Builder Harvest",
        email: `harvest-${Date.now()}@rea.local`,
        password: "harvest-password-1234",
      }),
    });
    if (!reg.ok || !cookieJar || !csrfToken) {
      throw new Error(`Harvest registration failed: ${JSON.stringify(reg)}`);
    }

    const jsonHdr = { "content-type": "application/json" };
    const upg = await jfetch("/api/billing/confirm-sandbox", {
      method: "POST",
      headers: jsonHdr,
      body: JSON.stringify({ plan_id: "ai_lab" }),
    });
    if (!upg.ok) {
      throw new Error(`Harvest sandbox upgrade failed: ${JSON.stringify(upg)}`);
    }

    const bootstrap = await jfetch("/api/bootstrap");
    delete bootstrap.csrf_token;

    const xrayBySample = {};
    for (const s of bootstrap.samples.electron) {
      xrayBySample[s.id] = await jfetch("/api/xray/scan", {
        method: "POST",
        headers: jsonHdr,
        body: JSON.stringify({ sample_id: s.id }),
      });
      delete xrayBySample[s.id].tenant;
    }

    const versionCompare = await jfetch("/api/xray/compare", {
      method: "POST",
      headers: jsonHdr,
      body: JSON.stringify({
        left: xrayBySample["acme-desktop-v1"].evidence_id,
        right: xrayBySample["acme-desktop-v2"].evidence_id,
      }),
    });
    delete versionCompare.tenant;

    const defaultTrace = await jfetch("/api/xray/trace", {
      method: "POST",
      headers: jsonHdr,
      body: JSON.stringify({
        evidence_id: xrayBySample["acme-desktop-v1"].evidence_id,
        seed_kind: "channel",
        seed_value: "shell:open-diagnostic",
      }),
    });
    delete defaultTrace.tenant;

    const shipgateBySample = {};
    for (const s of bootstrap.samples.binary) {
      shipgateBySample[s.id] = await jfetch("/api/shipgate/inspect", {
        method: "POST",
        headers: jsonHdr,
        body: JSON.stringify({ sample_id: s.id }),
      });
      delete shipgateBySample[s.id].tenant;
    }
    const elfSymbols = {};
    for (const sym of ["verify_license_pin", "vault_seal_frame"]) {
      elfSymbols[sym] = await jfetch("/api/shipgate/inspect", {
        method: "POST",
        headers: jsonHdr,
        body: JSON.stringify({ sample_id: "libvault-elf", symbol: sym }),
      });
      delete elfSymbols[sym].tenant;
    }

    const rlBySample = {};
    for (const s of bootstrap.samples.har) {
      rlBySample[s.id] = await jfetch("/api/rl/build", {
        method: "POST",
        headers: jsonHdr,
        body: JSON.stringify({ sample_id: s.id }),
      });
      delete rlBySample[s.id].tenant;
    }

    const evList = await jfetch("/api/evidence");
    const evDetails = {};
    const evMarkdown = {};
    for (const rec of evList.records.slice(0, 12)) {
      const det = await jfetch(`/api/evidence/${rec.evidence_id}`);
      const mdResp = await fetch(`${BASE}/api/evidence/${rec.evidence_id}/report?format=md`, {
        headers: { cookie: cookieJar },
      });
      evMarkdown[rec.evidence_id] = await mdResp.text();
      if (det.ok) {
        const copy = JSON.parse(JSON.stringify(det.record));
        delete copy.tenant_id;
        let trimmed = false;
        const preTrimId = copy.evidence?.evidence_id;
        if (copy.evidence?.normalized_result?.graph) {
          copy.evidence.normalized_result.graph = {
            nodes_preview: copy.evidence.normalized_result.graph.nodes?.slice(0, 8) ?? [],
            edges_preview: copy.evidence.normalized_result.graph.edges?.slice(0, 10) ?? [],
            note: "Full AST graph retained on server; trimmed in standalone view for mobile speed.",
          };
          trimmed = true;
        }
        if (copy.evidence?.normalized_result?.semantic_graph?.relations) {
          copy.evidence.normalized_result.semantic_graph.relations =
            copy.evidence.normalized_result.semantic_graph.relations.slice(0, 10);
          trimmed = true;
        }
        if (copy.evidence?.normalized_result?.records?.length > 6) {
          copy.evidence.normalized_result.records =
            copy.evidence.normalized_result.records.slice(0, 6);
          trimmed = true;
        }
        if (trimmed && ephemeral?.engine && copy.evidence && preTrimId) {
          copy.evidence.limitations = [
            ...(copy.evidence.limitations || []),
            `Standalone preview trim: large graph/record arrays were truncated for offline preview size; evidence_id commits to this trimmed preview (server redacted evidence_id: ${preTrimId}).`,
          ];
          copy.evidence.evidence_id = ephemeral.engine.computeAuthenticatedEvidenceId(copy.evidence);
          copy.preview_trimmed_from_evidence_id = preTrimId;
        }
        evDetails[rec.evidence_id] = copy;
      }
    }

    await jfetch("/api/auth/logout", { method: "POST", headers: jsonHdr }).catch(() => {});

    const ciWorkflowText = readFileSync("studio/ci/github-action-workflow.yml", "utf8");
    const ciCliText = readFileSync("studio/ci/shipgate-cli.mjs", "utf8");

    const snapshot = {
      bootstrap: {
        ...bootstrap,
        authenticated: false,
        tenant: null,
        api_keys: [],
      },
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

    const evidenceOnlyJson = JSON.stringify({
      xrayBySample,
      versionCompare,
      defaultTrace,
      shipgateBySample,
      elfSymbols,
      rlBySample,
      evRecords: snapshot.evRecords,
      evDetails,
      evMarkdown,
    });
    if (/caller_input_path|\/tmp\/|\/home\/|\/Users\/|rea-preview-build-|ten_/i.test(evidenceOnlyJson)) {
      throw new Error("SECURITY FAILURE: Unsanitized host path or tenant ID detected inside standalone Evidence snapshot!");
    }
    if (/local_path/i.test(JSON.stringify(evDetails))) {
      throw new Error("SECURITY FAILURE: local_path exposed inside ledger Evidence details!");
    }
    for (const m of evidenceOnlyJson.matchAll(/"local_path"\\s*:\\s*"([^"]*)"/g)) {
      if (m[1].includes("/") || m[1].includes("\\")) {
        throw new Error(`SECURITY FAILURE: Directory path found inside RL local_path: ${m[1]}`);
      }
    }

    const html = readFileSync("studio/public/index.html", "utf8");
    const css = readFileSync("studio/public/styles.css", "utf8");
    const js = readFileSync("studio/public/app.js", "utf8");
    const safeSnapshotJson = JSON.stringify(snapshot).replaceAll("<", "\\u003c");

    const offlineEngineShim = `
const SNAPSHOT = ${safeSnapshotJson};
let STATIC_MODE = false;

const localSim = {
  authenticated: false,
  csrfToken: "",
  tenant: null,
  keys: [],
  rlStates: {},
};

function mkJsonResp(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mkBlobResp(status, mime, filename, content) {
  return new Response(content, {
    status,
    headers: {
      "content-type": mime,
      "content-disposition": 'attachment; filename="' + filename + '"',
    },
  });
}

function rejectStaticUpload() {
  return mkJsonResp(403, {
    ok: false,
    error: {
      code: "static_preview_uploads_disabled",
      message:
        "Custom file uploads are disabled in static preview mode so uninspected artifacts are never falsely certified. Run the live REA Cloud Studio server to inspect custom files.",
    },
  });
}

function requireStaticSession() {
  if (!localSim.authenticated || !localSim.tenant) {
    return mkJsonResp(401, {
      ok: false,
      error: {
        code: "unauthorized",
        message: "Sign in or create a local preview workspace to view pre-computed REA samples.",
      },
    });
  }
  return null;
}

async function handleEmbeddedApi(path, init = {}) {
  STATIC_MODE = true;

  if (path === "/api/upload") {
    return rejectStaticUpload();
  }

  const body = init.body && typeof init.body === "string" ? JSON.parse(init.body) : {};

  if (path === "/api/bootstrap") {
    return mkJsonResp(200, {
      ...SNAPSHOT.bootstrap,
      authenticated: localSim.authenticated,
      csrf_token: localSim.authenticated ? localSim.csrfToken : null,
      tenant: localSim.tenant,
      api_keys: localSim.authenticated ? localSim.keys : [],
    });
  }

  if (path === "/api/auth/register" || path === "/api/auth/login") {
    if (!body.email || !body.password || String(body.password).length < 8) {
      return mkJsonResp(400, {
        ok: false,
        error: { code: "invalid_credentials", message: "Provide email and password (min 8 chars)." },
      });
    }
    localSim.authenticated = true;
    localSim.csrfToken = "csrf_static_preview";
    localSim.tenant = {
      id: "ten_static_preview",
      email: body.email,
      org_name: body.org_name || String(body.email).split("@")[0] || "Preview Workspace",
      plan_id: "free_trial",
      plan_name: "Free Developer Trial (Static Sample Preview)",
      plan_badge: "Preview",
      price_monthly_usd: 0,
      usage: { scans_used: 0, scan_limit: 5, rl_builds_used: 0, rl_build_limit: 2 },
    };
    const previewSecret = "rea_sk_preview_only_non_live";
    localSim.keys = [{ id: "key_preview", name: "Static Preview Key", prefix: "rea_sk_preview_****", calls: 0 }];
    return mkJsonResp(200, {
      ok: true,
      csrf_token: localSim.csrfToken,
      tenant: localSim.tenant,
      starter_api_key: { id: "key_preview", name: "Static Preview Key", prefix: "rea_sk_preview_****", secret_token: previewSecret },
      api_keys: localSim.keys,
    });
  }

  if (path === "/api/auth/logout") {
    localSim.authenticated = false;
    localSim.csrfToken = "";
    localSim.tenant = null;
    localSim.keys = [];
    return mkJsonResp(200, { ok: true, revoked: true });
  }

  if (path === "/api/ci/github-action.yml") {
    return mkBlobResp(200, "text/yaml; charset=utf-8", "rea-shipgate.yml", SNAPSHOT.ciWorkflowText);
  }
  if (path === "/api/ci/shipgate-cli.mjs") {
    return mkBlobResp(200, "application/javascript; charset=utf-8", "shipgate-cli.mjs", SNAPSHOT.ciCliText);
  }

  const unauth = requireStaticSession();
  if (unauth) return unauth;

  if (path === "/api/evidence") {
    return mkJsonResp(200, { ok: true, tenant: localSim.tenant, records: SNAPSHOT.evRecords });
  }
  if (path.startsWith("/api/evidence/") && path.includes("/report")) {
    const id = decodeURIComponent(path.split("/api/evidence/")[1].split("/")[0]);
    if (path.includes("format=json")) {
      const rec = SNAPSHOT.evDetails[id];
      if (!rec) return mkJsonResp(404, { ok: false, error: { message: "Not found" } });
      return mkBlobResp(200, "application/json", id.slice(0, 16) + ".evidence.json", JSON.stringify(rec.evidence, null, 2));
    }
    const md = SNAPSHOT.evMarkdown[id];
    if (!md) return mkJsonResp(404, { ok: false, error: { message: "Not found" } });
    return mkBlobResp(200, "text/markdown; charset=utf-8", id.slice(0, 16) + "-audit.md", md);
  }
  if (path.startsWith("/api/evidence/")) {
    const id = decodeURIComponent(path.replace("/api/evidence/", "").split("/")[0]);
    const rec = SNAPSHOT.evDetails[id];
    if (!rec) return mkJsonResp(404, { ok: false, error: { message: "Evidence not in static sample snapshot" } });
    return mkJsonResp(200, { ok: true, record: rec, tenant: localSim.tenant });
  }
  if (path === "/api/xray/scan") {
    if (body.saved_path) return rejectStaticUpload();
    const hit = SNAPSHOT.xrayBySample[body.sample_id];
    if (!hit) return mkJsonResp(404, { ok: false, error: { message: "Sample not found in static snapshot" } });
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path === "/api/xray/compare") {
    return mkJsonResp(200, { ...SNAPSHOT.versionCompare, tenant: localSim.tenant });
  }
  if (path === "/api/xray/trace") {
    return mkJsonResp(200, {
      ...SNAPSHOT.defaultTrace,
      trace: {
        ...SNAPSHOT.defaultTrace.trace,
        queried_seed: { kind: body.seed_kind, value: body.seed_value, direction: body.direction },
      },
      tenant: localSim.tenant,
    });
  }
  if (path === "/api/shipgate/inspect") {
    if (body.saved_path) return rejectStaticUpload();
    if (body.sample_id === "libvault-elf" && body.symbol && SNAPSHOT.elfSymbols[body.symbol]) {
      return mkJsonResp(200, { ...SNAPSHOT.elfSymbols[body.symbol], tenant: localSim.tenant });
    }
    const hit = SNAPSHOT.shipgateBySample[body.sample_id];
    if (!hit) return mkJsonResp(404, { ok: false, error: { message: "Sample not found in static snapshot" } });
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path === "/api/rl/build") {
    if (body.saved_path) return rejectStaticUpload();
    const hit = JSON.parse(JSON.stringify(SNAPSHOT.rlBySample[body.sample_id] || SNAPSHOT.rlBySample["helpdesk-crm"]));
    localSim.rlStates[hit.env_id] = JSON.parse(JSON.stringify(hit.state_snapshot));
    return mkJsonResp(200, { ...hit, tenant: localSim.tenant });
  }
  if (path.startsWith("/api/rl/download/")) {
    return mkJsonResp(403, {
      ok: false,
      error: { message: "AgentEnv .zip synthesis requires the live REA Cloud Studio server." },
    });
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
  if (path === "/api/billing/checkout" || path === "/api/billing/confirm-sandbox") {
    return mkJsonResp(403, {
      ok: false,
      error: { code: "static_preview_billing_disabled", message: "Billing requires the live Studio backend." },
    });
  }
  return mkJsonResp(404, { ok: false, error: { message: "Offline preview route not cached" } });
}

const _nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const isHttpHost = (window.location.protocol === "http:" || window.location.protocol === "https:") && Boolean(window.location.host);
  const isStaticHost = STATIC_MODE || /github\\.io$|githack\\.com$|githubusercontent\\.com$/.test(window.location.hostname);
  if (typeof input === "string" && input.startsWith("/api/")) {
    if (isHttpHost && !isStaticHost) {
      try {
        const liveResp = await _nativeFetch(input, init);
        const ct = liveResp.headers.get("content-type") || "";
        if (
          liveResp.status < 500 &&
          (ct.includes("application/json") ||
            ct.includes("text/markdown") ||
            ct.includes("application/zip") ||
            ct.includes("text/yaml") ||
            ct.includes("application/javascript"))
        ) {
          return liveResp;
        }
      } catch {
        // Fall through to embedded static sample snapshot
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
    console.log(`Built studio/index.html (${(outHtml.length / 1024).toFixed(1)} KiB) — zero host paths verified.`);
  } finally {
    await ephemeral?.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
