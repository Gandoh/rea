#!/usr/bin/env node
// ============================================================================
// REA Cloud Studio — external smoke test (dependency-free, Node built-ins only)
//
//   node studio/scripts/smoke-external.mjs [baseUrl] [--sample-id=acme-desktop-v1]
//
//   baseUrl defaults to REA_SMOKE_BASE_URL or http://127.0.0.1:3080
//
// What it does (all against the given base URL):
//   1. GET  /api/health                       -> expects { ok: true, ... }
//   2. GET  /api/kelviq/status                 -> ABORTS unless billing is inert
//   3. POST /api/auth/register                 -> disposable random account
//   4. POST /api/auth/login                    -> fresh session cookie
//   5. GET  /api/bootstrap                     -> CSRF token
//   6. POST /api/xray/scan { sample_id }       -> ONE REAL AppScope X-Ray scan
//
// Safety properties:
//   - Uses only disposable, randomly generated credentials (example.test).
//   - Never calls any billing / webhook / payment endpoint.
//   - Refuses to run when the target reports live payment keys configured.
//   - Exit code 0 only if every step passed.
// ============================================================================

import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_SAMPLE_ID = "acme-desktop-v1";
const BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 REA-Smoke-Test";

/** Build a disposable, non-existent test email address. */
export function buildDisposableEmail(now = Date.now(), rand = randomBytes(4).toString("hex")) {
  return `rea-smoke-${now.toString(36)}-${rand}@example.test`;
}

/** Build a strong disposable password. */
export function buildDisposablePassword(rand = randomBytes(12).toString("hex")) {
  return `Smoke-${rand}-Aa1!${randomBytes(2).toString("hex")}`;
}

/**
 * Throw unless the target's Kelviq status proves no live payment path is
 * configured. This is what makes it impossible for this smoke test to trigger
 * a payment: we never proceed against a billing-enabled instance, and we
 * never call any billing endpoint at all.
 */
export function assertBillingInert(kelviq) {
  if (!kelviq || typeof kelviq !== "object") {
    throw new Error("kelviq status missing from /api/kelviq/status response");
  }
  if (kelviq.live_keys_configured === true) {
    throw new Error("ABORT: target has live billing keys configured (live_keys_configured=true) — refusing to smoke-test a billing-enabled instance.");
  }
  if (kelviq.direct_usdt_enabled === true) {
    throw new Error("ABORT: target has direct USDT payments enabled — refusing to smoke-test.");
  }
  if (kelviq.sandbox_enabled === true) {
    throw new Error("ABORT: target has sandbox self-provisioning billing enabled — refusing to smoke-test.");
  }
}

/** Parse and sanity-check the base URL (https required unless loopback). */
export function parseBaseUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid base URL: ${raw}`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`Base URL must be https:// (http is allowed only for loopback testing): ${raw}`);
  }
  return url;
}

function parseArgs(argv) {
  let baseUrl = process.env.REA_SMOKE_BASE_URL || "http://127.0.0.1:3080";
  let sampleId = DEFAULT_SAMPLE_ID;
  for (const arg of argv) {
    if (arg.startsWith("--sample-id=")) sampleId = arg.slice("--sample-id=".length);
    else if (!arg.startsWith("--")) baseUrl = arg;
  }
  return { baseUrl, sampleId };
}

class CookieJar {
  constructor() {
    this.map = new Map();
  }
  store(res) {
    for (const line of res.headers.getSetCookie?.() || []) {
      const pair = line.split(";")[0];
      const eq = pair.indexOf("=");
      if (eq > 0) this.map.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  header() {
    return [...this.map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function request(base, path, { method = "GET", body, jar, csrf } = {}) {
  const headers = {
    "user-agent": BROWSER_UA,
    origin: base.origin,
    accept: "application/json",
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (jar) {
    const cookie = jar.header();
    if (cookie) headers.cookie = cookie;
  }
  if (csrf) headers["x-csrf-token"] = csrf;
  const res = await fetch(new URL(path, base), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(path === "/api/xray/scan" ? 180_000 : 20_000),
  });
  if (jar) jar.store(res);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

function step(name) {
  process.stdout.write(`[ .. ] ${name} ... `);
}
function pass(name, detail) {
  console.log(`[PASS] ${name}${detail ? ` — ${detail}` : ""}`);
}
function fail(name, detail) {
  console.log(`[FAIL] ${name}${detail ? ` — ${detail}` : ""}`);
}

export async function runSmokeTest({ baseUrl, sampleId }) {
  const base = parseBaseUrl(baseUrl);
  const jar = new CookieJar();
  const summary = { base_url: base.origin, sample_id: sampleId, steps: {}, ok: false };
  const results = [];

  // 1) health
  step("GET /api/health");
  const health = await request(base, "/api/health", { jar });
  if (health.status === 200 && health.json?.ok === true) {
    summary.steps.health = { ok: true, rea_version: health.json.rea_version, mcp_tools: health.json.mcp_tools };
    pass("GET /api/health", `ok=true rea_version=${health.json.rea_version} mcp_tools=${health.json.mcp_tools}`);
  } else {
    summary.steps.health = { ok: false, status: health.status, body: health.text?.slice(0, 200) };
    fail("GET /api/health", `status=${health.status} body=${health.text?.slice(0, 200)}`);
    return summary;
  }

  // 2) billing must be inert (payment-safety guard)
  step("GET /api/kelviq/status (billing-inert guard)");
  const kelviqStatus = await request(base, "/api/kelviq/status", { jar });
  try {
    assertBillingInert(kelviqStatus.json?.kelviq);
    summary.steps.billing_inert = { ok: true, ...kelviqStatus.json.kelviq };
    pass("billing inert on target", `live_keys_configured=${kelviqStatus.json.kelviq.live_keys_configured} sandbox_enabled=${kelviqStatus.json.kelviq.sandbox_enabled} direct_usdt_enabled=${kelviqStatus.json.kelviq.direct_usdt_enabled}`);
  } catch (err) {
    summary.steps.billing_inert = { ok: false, error: String(err.message || err) };
    fail("billing-inert guard", String(err.message || err));
    return summary;
  }

  // 3) disposable registration
  const email = buildDisposableEmail();
  const password = buildDisposablePassword();
  summary.disposable_email = email;
  step(`POST /api/auth/register (disposable ${email})`);
  const register = await request(base, "/api/auth/register", {
    method: "POST",
    jar,
    body: { org_name: "REA Smoke Test", email, password },
  });
  if (register.status === 200 && register.json?.ok === true) {
    summary.steps.register = { ok: true, tenant: register.json.tenant?.id, plan: register.json.tenant?.plan_id };
    pass("register", `tenant=${register.json.tenant?.id} plan=${register.json.tenant?.plan_id}`);
  } else {
    summary.steps.register = { ok: false, status: register.status, body: register.text?.slice(0, 300) };
    fail("register", `status=${register.status} body=${register.text?.slice(0, 300)}`);
    return summary;
  }

  // 4) login (fresh session)
  step("POST /api/auth/login");
  const login = await request(base, "/api/auth/login", { method: "POST", jar, body: { email, password } });
  if (login.status === 200 && login.json?.ok === true) {
    summary.steps.login = { ok: true, tenant: login.json.tenant?.id };
    pass("login", `tenant=${login.json.tenant?.id}`);
  } else {
    summary.steps.login = { ok: false, status: login.status, body: login.text?.slice(0, 300) };
    fail("login", `status=${login.status} body=${login.text?.slice(0, 300)}`);
    return summary;
  }

  // 5) CSRF token from bootstrap
  step("GET /api/bootstrap (CSRF)");
  const bootstrap = await request(base, "/api/bootstrap", { jar });
  const csrf = bootstrap.json?.csrf_token;
  if (bootstrap.status === 200 && bootstrap.json?.ok === true && typeof csrf === "string" && csrf) {
    summary.steps.csrf = { ok: true };
    pass("csrf token", `${csrf.slice(0, 8)}…`);
  } else {
    summary.steps.csrf = { ok: false, status: bootstrap.status, body: bootstrap.text?.slice(0, 300) };
    fail("csrf token", `status=${bootstrap.status} authenticated=${bootstrap.json?.authenticated}`);
    return summary;
  }

  // 6) ONE REAL AppScope X-Ray scan of the bundled sample
  step(`POST /api/xray/scan (${sampleId}) — real scan`);
  const started = Date.now();
  const scan = await request(base, "/api/xray/scan", {
    method: "POST",
    jar,
    csrf,
    body: { sample_id: sampleId },
  });
  const wallMs = Date.now() - started;
  if (scan.status === 200 && scan.json?.ok === true) {
    const p = scan.json.posture || {};
    summary.steps.xray_scan = {
      ok: true,
      elapsed_ms: scan.json.elapsed_ms,
      wall_ms: wallMs,
      score: p.score,
      grade: p.grade,
      release_gate: p.release_gate,
      evidence_id: scan.json.evidence_id,
    };
    pass("xray scan", `score=${p.score} grade=${p.grade} gate=${p.release_gate} evidence=${String(scan.json.evidence_id || "").slice(0, 12)}… (${wallMs} ms wall)`);
  } else {
    summary.steps.xray_scan = { ok: false, status: scan.status, body: scan.text?.slice(0, 300) };
    fail("xray scan", `status=${scan.status} body=${scan.text?.slice(0, 300)}`);
    return summary;
  }

  summary.ok = true;
  return summary;
}

async function main() {
  const { baseUrl, sampleId } = parseArgs(process.argv.slice(2));
  console.log(`REA Studio external smoke test → ${baseUrl} (sample: ${sampleId})`);
  console.log("Note: no billing/webhook endpoints are called; target must report billing inert.");
  const summary = await runSmokeTest({ baseUrl, sampleId });
  console.log("\n=== smoke summary ===");
  console.log(JSON.stringify(summary, null, 2));
  if (summary.ok) {
    console.log("\nRESULT: PASS — health, register, login, CSRF and one real X-Ray scan all succeeded; billing verified inert; disposable account only.");
    process.exitCode = 0;
  } else {
    console.log("\nRESULT: FAIL — see failed step above.");
    process.exitCode = 1;
  }
}

const invokedAsScript =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (invokedAsScript) {
  main().catch((err) => {
    console.error(`[FAIL] smoke test crashed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
