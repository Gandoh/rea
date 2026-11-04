// Production startup configuration validator for REA Cloud Studio.
//
// Pure and side-effect free: it only reads the env object it is given, so it
// can be unit-tested without booting the server. `studio/server/index.mjs`
// calls validateStartupConfig(process.env) at module load and refuses to boot
// in NODE_ENV=production when any FATAL error is present.
//
// Contract (preserved from the existing security suite):
// - A MISSING PUBLIC_BASE_URL is reported as an error but is NOT fatal: the
//   server keeps booting and fails closed per request with
//   503 "missing_public_base_url" (tested in p0-security.test.mjs).
// - UNSAFE values (non-https PUBLIC_BASE_URL, unsafe CORS entries, ephemeral
//   data dir, invalid port, ALLOW_SANDBOX_BILLING=true) are fatal at boot.
//
// Security notes:
// - Never log or return secret VALUES. summarizeSafeConfig() reports only
//   presence flags for key-like variables.
// - "production" is matched case-insensitively (stricter than the per-request
//   checks, intentionally).

import { existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const EPHEMERAL_ROOTS = ["/tmp", "/var/tmp", "/private/tmp"];

function resolveRealOrLexicalPath(targetPath) {
  const lex = resolve(String(targetPath || ""));
  let probe = lex;
  const suffixParts = [];
  while (!existsSync(probe)) {
    const parent = dirname(probe);
    if (parent === probe) break;
    suffixParts.unshift(basename(probe));
    probe = parent;
  }
  try {
    const realBase = existsSync(probe) ? realpathSync(probe) : probe;
    return suffixParts.length > 0 ? resolve(realBase, ...suffixParts) : realBase;
  } catch {
    return lex;
  }
}

function isEphemeralPath(targetPath) {
  const resolved = resolveRealOrLexicalPath(targetPath);
  const sysTmp = resolveRealOrLexicalPath(tmpdir());
  const roots = new Set([sysTmp, ...EPHEMERAL_ROOTS].map((p) => p.replace(/\/+$/u, "")));
  return Array.from(roots).some(
    (root) => root.length > 0 && (resolved === root || resolved.startsWith(`${root}/`)),
  );
}

export function isProductionEnv(env) {
  return String(env?.NODE_ENV || "").toLowerCase() === "production";
}

function parseOriginList(raw) {
  return String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function isLoopbackHostname(hostname) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1"
  );
}

/**
 * Validate startup configuration.
 * @param {NodeJS.ProcessEnv} env
 * @returns {{
 *   ok: boolean, production: boolean,
 *   errors: string[],        // all problems (missing or unsafe), always reported
 *   fatalErrors: string[],   // unsafe problems that abort startup
 *   warnings: string[],
 * }}
 */
export function validateStartupConfig(env = process.env) {
  const errors = [];
  const fatalErrors = [];
  const warnings = [];
  const production = isProductionEnv(env);
  const fatal = (msg) => {
    errors.push(msg);
    fatalErrors.push(msg);
  };

  if (!production) {
    // Development / sandbox behaviour is intentionally unchanged.
    return { ok: true, production, errors, fatalErrors, warnings };
  }

  // --- PUBLIC_BASE_URL: required, must be https (loopback excepted) --------
  const publicBaseUrl = String(env.PUBLIC_BASE_URL || "").trim();
  if (!publicBaseUrl) {
    // Non-fatal on purpose: per-request fail-closed (503) contract is tested
    // by p0-security.test.mjs and must be preserved.
    errors.push(
      "missing_public_base_url: PUBLIC_BASE_URL is not set. The server still boots, but every " +
        "endpoint that needs it (e.g. billing checkout redirects) fails closed with 503 " +
        "missing_public_base_url until you set it to the exact public https:// origin.",
    );
  } else {
    let parsed = null;
    try {
      parsed = new URL(publicBaseUrl);
    } catch {
      fatal(`unsafe_public_base_url: PUBLIC_BASE_URL (${publicBaseUrl}) is not a valid absolute URL.`);
    }
    if (parsed) {
      if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname))) {
        fatal(`unsafe_public_base_url: PUBLIC_BASE_URL must use https: in production (got ${parsed.protocol}//${parsed.hostname}).`);
      }
      if (parsed.username || parsed.password) {
        fatal("unsafe_public_base_url: PUBLIC_BASE_URL must not embed credentials.");
      }
      if ((parsed.pathname && parsed.pathname !== "/") || parsed.search || parsed.hash) {
        fatal("unsafe_public_base_url: PUBLIC_BASE_URL must be a bare origin without path, query, or fragment.");
      }
    }
  }

  // --- CORS_ALLOWED_ORIGINS: optional, but every entry must be a safe origin -
  for (const entry of parseOriginList(env.CORS_ALLOWED_ORIGINS)) {
    let parsed = null;
    try {
      parsed = new URL(entry);
    } catch {
      fatal(`unsafe_cors_origin: CORS_ALLOWED_ORIGINS entry "${entry}" is not a valid absolute origin.`);
      continue;
    }
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname))) {
      fatal(`unsafe_cors_origin: CORS_ALLOWED_ORIGINS entry "${entry}" must use https: in production.`);
    }
    if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      fatal(`unsafe_cors_origin: CORS_ALLOWED_ORIGINS entry "${entry}" must be a bare origin.`);
    }
  }
  if (!String(env.CORS_ALLOWED_ORIGINS || "").trim()) {
    warnings.push(
      "CORS_ALLOWED_ORIGINS is empty: only same-origin browser calls will be accepted. " +
        "Set it (comma-separated exact origins) if the dashboard is hosted on a different origin.",
    );
  }

  // --- Persistent data directory -------------------------------------------
  // Mirror the effective-path logic of index.mjs exactly.
  const runtimeDir = String(env.REA_STUDIO_RUNTIME_DIR || "/tmp/rea-studio-runtime");
  const effectiveDataDir = String(
    env.REA_STUDIO_DATA_DIR || env.STUDIO_DATA_DIR || join(runtimeDir, "data"),
  ).trim();
  if (isEphemeralPath(effectiveDataDir)) {
    fatal(
      `unsafe_data_dir: effective REA_STUDIO_DATA_DIR (${resolve(effectiveDataDir)}) resolves to ephemeral /tmp storage. ` +
        "Mount a persistent volume (e.g. /data) and point REA_STUDIO_DATA_DIR at it.",
    );
  }

  // --- Port ------------------------------------------------------------------
  const portRaw = String(env.PORT || "3000").trim();
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    fatal(`unsafe_port: PORT (${portRaw}) must be an integer between 1 and 65535.`);
  }

  // --- Payment-path guards (billing must stay off unless deliberately enabled) -
  if (String(env.ALLOW_SANDBOX_BILLING || "").toLowerCase() === "true") {
    fatal(
      "unsafe_billing_flag: ALLOW_SANDBOX_BILLING=true is forbidden in NODE_ENV=production " +
        "(sandbox self-provisioning must never be enabled on a public instance).",
    );
  }
  if (String(env.ALPHASHIELD_ENABLE_DIRECT_USDT || "").toLowerCase() === "true") {
    warnings.push(
      "ALPHASHIELD_ENABLE_DIRECT_USDT=true: direct on-chain USDT payment path is enabled. " +
        "Verify this is intentional; it is not required for free-tier operation.",
    );
  }
  const keyLikeVars = [
    "KELVIQ_SERVER_API_KEY",
    "KELVIQ_CLIENT_API_KEY",
    "KELVIQ_WEBHOOK_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "REA_BOOTSTRAP_API_KEY",
  ];
  const presentKeys = keyLikeVars.filter((name) => String(env[name] || "").trim().length > 0);
  if (presentKeys.length > 0) {
    warnings.push(
      `key_material_present: ${presentKeys.join(", ")} — values are never logged. ` +
        "If this instance is meant to run with billing disabled, unset these.",
    );
  }
  if (String(env.KELVIQ_ENV || "").toLowerCase() === "production" && !String(env.KELVIQ_SERVER_API_KEY || "").trim()) {
    warnings.push("KELVIQ_ENV=production but KELVIQ_SERVER_API_KEY is empty: billing endpoints will report 'not configured'.");
  }

  return { ok: fatalErrors.length === 0, production, errors, fatalErrors, warnings };
}

/**
 * Redacted startup summary for logs. NEVER includes secret values — only
 * booleans for key-like variables and non-secret settings.
 * @param {NodeJS.ProcessEnv} env
 */
export function summarizeSafeConfig(env = process.env) {
  const keyLikeVars = [
    "KELVIQ_SERVER_API_KEY",
    "KELVIQ_CLIENT_API_KEY",
    "KELVIQ_WEBHOOK_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "REA_BOOTSTRAP_API_KEY",
  ];
  const keysPresent = {};
  for (const name of keyLikeVars) {
    keysPresent[name] = String(env[name] || "").trim().length > 0;
  }
  return {
    NODE_ENV: env.NODE_ENV || "",
    HOST: env.HOST || "0.0.0.0",
    PORT: env.PORT || "3000",
    PUBLIC_BASE_URL: env.PUBLIC_BASE_URL || "",
    CORS_ALLOWED_ORIGINS: env.CORS_ALLOWED_ORIGINS || "",
    REA_STUDIO_DATA_DIR: env.REA_STUDIO_DATA_DIR || env.STUDIO_DATA_DIR || "",
    REA_STUDIO_RUNTIME_DIR: env.REA_STUDIO_RUNTIME_DIR || "",
    KELVIQ_ENV: env.KELVIQ_ENV || "",
    ALLOW_SANDBOX_BILLING: String(env.ALLOW_SANDBOX_BILLING || "").toLowerCase() === "true",
    ALPHASHIELD_ENABLE_DIRECT_USDT: String(env.ALPHASHIELD_ENABLE_DIRECT_USDT || "").toLowerCase() === "true",
    key_material_present: keysPresent,
  };
}
