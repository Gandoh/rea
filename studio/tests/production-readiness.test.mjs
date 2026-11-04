// Production startup-configuration readiness tests (Milestone 1).
// Covers studio/server/configValidation.mjs (validator + redacted summary) and
// the payment-safety guard of studio/scripts/smoke-external.mjs.

import test from "node:test";
import assert from "node:assert/strict";

import { summarizeSafeConfig, validateStartupConfig } from "../server/configValidation.mjs";
import { assertBillingInert, buildDisposableEmail, parseBaseUrl } from "../scripts/smoke-external.mjs";

const VALID_PROD = {
  NODE_ENV: "production",
  PUBLIC_BASE_URL: "https://studio.example.com",
  CORS_ALLOWED_ORIGINS: "https://studio.example.com",
  REA_STUDIO_DATA_DIR: "/data/rea-studio",
  PORT: "3080",
};

test("production validator accepts a valid production config", () => {
  const result = validateStartupConfig({ ...VALID_PROD });
  assert.equal(result.production, true);
  assert.equal(result.ok, true, `unexpected errors: ${result.errors.join(" | ")}`);
  assert.deepEqual(result.errors, []);
});

test("production validator reports missing PUBLIC_BASE_URL as a non-fatal error (fail-closed contract preserved)", () => {
  const { PUBLIC_BASE_URL, ...env } = VALID_PROD;
  const result = validateStartupConfig(env);
  // Server may still boot, but the problem is clearly reported, not hidden.
  assert.equal(result.ok, true, "missing PUBLIC_BASE_URL must not abort boot (per-request 503 fail-closed)");
  assert.ok(result.errors.some((e) => e.startsWith("missing_public_base_url")));
  assert.equal(result.fatalErrors.length, 0);
});

test("production validator rejects non-https PUBLIC_BASE_URL", () => {
  const result = validateStartupConfig({ ...VALID_PROD, PUBLIC_BASE_URL: "http://studio.example.com" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.startsWith("unsafe_public_base_url")));
});

test("production validator allows http PUBLIC_BASE_URL only for loopback", () => {
  const okLoopback = validateStartupConfig({ ...VALID_PROD, PUBLIC_BASE_URL: "http://127.0.0.1:3080" });
  assert.equal(okLoopback.ok, true, `unexpected errors: ${okLoopback.errors.join(" | ")}`);
  const bad = validateStartupConfig({ ...VALID_PROD, PUBLIC_BASE_URL: "http://192.168.1.10:3080" });
  assert.equal(bad.ok, false);
});

test("production validator rejects PUBLIC_BASE_URL with path/query/credentials", () => {
  for (const bad of [
    "https://studio.example.com/app",
    "https://studio.example.com?x=1",
    "https://user:pass@studio.example.com",
  ]) {
    const result = validateStartupConfig({ ...VALID_PROD, PUBLIC_BASE_URL: bad });
    assert.equal(result.ok, false, `expected rejection for ${bad}`);
    assert.ok(result.errors.some((e) => e.startsWith("unsafe_public_base_url")));
  }
});

test("production validator rejects unsafe CORS entries but accepts https origins", () => {
  const bad = validateStartupConfig({ ...VALID_PROD, CORS_ALLOWED_ORIGINS: "https://ok.example.com,not-a-url,http://evil.example.com" });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.filter((e) => e.startsWith("unsafe_cors_origin")).length === 2);
  const good = validateStartupConfig({ ...VALID_PROD, CORS_ALLOWED_ORIGINS: "https://a.example.com, https://b.example.com" });
  assert.equal(good.ok, true, `unexpected errors: ${good.errors.join(" | ")}`);
});

test("production validator rejects ephemeral effective data dir (fatal)", () => {
  const tmpDir = validateStartupConfig({ ...VALID_PROD, REA_STUDIO_DATA_DIR: "/tmp/rea-studio-data" });
  assert.equal(tmpDir.ok, false);
  assert.ok(tmpDir.fatalErrors.some((e) => e.startsWith("unsafe_data_dir")));
  // Unset DATA_DIR but persistent RUNTIME_DIR -> effective dir is persistent -> OK
  const okRuntime = validateStartupConfig({ ...VALID_PROD, REA_STUDIO_DATA_DIR: "", STUDIO_DATA_DIR: "", REA_STUDIO_RUNTIME_DIR: "/data/rt" });
  assert.equal(okRuntime.ok, true, `unexpected errors: ${okRuntime.errors.join(" | ")}`);
  // Unset both -> defaults under /tmp -> fatal
  const defaultTmp = validateStartupConfig({ ...VALID_PROD, REA_STUDIO_DATA_DIR: "", STUDIO_DATA_DIR: "", REA_STUDIO_RUNTIME_DIR: "" });
  assert.equal(defaultTmp.ok, false);
  assert.ok(defaultTmp.fatalErrors.some((e) => e.startsWith("unsafe_data_dir")));
});

test("production validator rejects invalid PORT", () => {
  for (const port of ["0", "70000", "abc"]) {
    const result = validateStartupConfig({ ...VALID_PROD, PORT: port });
    assert.equal(result.ok, false, `expected rejection for PORT=${port}`);
    assert.ok(result.errors.some((e) => e.startsWith("unsafe_port")));
  }
});

test("production validator forbids ALLOW_SANDBOX_BILLING=true in production", () => {
  const result = validateStartupConfig({ ...VALID_PROD, ALLOW_SANDBOX_BILLING: "true" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.startsWith("unsafe_billing_flag")));
});

test("non-production env is always accepted (dev behavior unchanged)", () => {
  const result = validateStartupConfig({ NODE_ENV: "development" });
  assert.equal(result.production, false);
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  const empty = validateStartupConfig({});
  assert.equal(empty.ok, true);
});

test("NODE_ENV matching is case-insensitive for the production gate", () => {
  const result = validateStartupConfig({ ...VALID_PROD, NODE_ENV: "Production" });
  assert.equal(result.production, true);
  assert.equal(result.ok, true);
});

test("summarizeSafeConfig never leaks secret values, only presence flags", () => {
  const secret = "sk_live_super_secret_value_123";
  const summary = summarizeSafeConfig({ ...VALID_PROD, KELVIQ_SERVER_API_KEY: secret, REA_BOOTSTRAP_API_KEY: "rea_sk_live_bootstrap" });
  const serialized = JSON.stringify(summary);
  assert.ok(!serialized.includes(secret), "summary must not contain the secret value");
  assert.ok(!serialized.includes("rea_sk_live_bootstrap"), "summary must not contain bootstrap key value");
  assert.equal(summary.key_material_present.KELVIQ_SERVER_API_KEY, true);
  assert.equal(summary.key_material_present.REA_BOOTSTRAP_API_KEY, true);
  assert.equal(summary.key_material_present.STRIPE_SECRET_KEY, false);
  assert.equal(summary.PUBLIC_BASE_URL, "https://studio.example.com");
});

test("smoke-test guard aborts when live billing is configured", () => {
  assert.throws(() => assertBillingInert({ live_keys_configured: true, sandbox_enabled: false, direct_usdt_enabled: false }), /live billing keys/);
  assert.throws(() => assertBillingInert({ live_keys_configured: false, sandbox_enabled: true, direct_usdt_enabled: false }), /self-provisioning/);
  assert.throws(() => assertBillingInert({ live_keys_configured: false, sandbox_enabled: false, direct_usdt_enabled: true }), /USDT/);
  assert.doesNotThrow(() => assertBillingInert({ live_keys_configured: false, sandbox_enabled: false, direct_usdt_enabled: false }));
  assert.throws(() => assertBillingInert(null), /missing/);
});

test("smoke-test helpers: disposable email + base URL rules", () => {
  const email = buildDisposableEmail(1700000000000, "deadbeef");
  assert.match(email, /^rea-smoke-[a-z0-9]+-deadbeef@example\.test$/);
  assert.doesNotThrow(() => parseBaseUrl("https://studio.example.com"));
  assert.doesNotThrow(() => parseBaseUrl("http://127.0.0.1:3080"));
  assert.throws(() => parseBaseUrl("http://example.com"), /https/);
  assert.throws(() => parseBaseUrl("not a url"), /Invalid base URL/);
});
