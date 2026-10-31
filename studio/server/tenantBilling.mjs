import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { backupSqliteDatabase } from "../scripts/sqliteBackup.mjs";

export const PLANS = Object.freeze({
  free_trial: {
    id: "free_trial",
    name: "Free Developer Trial",
    price_monthly_usd: 0,
    unit_amount_cents: 0,
    scan_limit: 5,
    rl_build_limit: 2,
    max_api_keys: 2,
    badge: "Trial",
  },
  indie: {
    id: "indie",
    name: "Researcher / Indie",
    price_monthly_usd: 49,
    unit_amount_cents: 4900,
    scan_limit: 50,
    rl_build_limit: 5,
    max_api_keys: 5,
    badge: "$49/mo",
  },
  team: {
    id: "team",
    name: "ShipGate Team CI/CD",
    price_monthly_usd: 299,
    unit_amount_cents: 29900,
    scan_limit: null,
    rl_build_limit: 15,
    max_api_keys: 20,
    badge: "$299/mo",
  },
  ai_lab: {
    id: "ai_lab",
    name: "AI Lab RL Factory",
    price_monthly_usd: 1499,
    unit_amount_cents: 149900,
    scan_limit: null,
    rl_build_limit: null,
    max_api_keys: 100,
    badge: "$1,499/mo",
  },
});

export const ALPHASHIELD_ENTITLEMENT_PLANS = Object.freeze({
  free_trial: { id: "free_trial", name: "AlphaShield Free Starter", daily_scans: 3 },
  alphashield_pro: { id: "alphashield_pro", name: "AlphaShield Pro Trader", daily_scans: null },
  alphashield_whale: { id: "alphashield_whale", name: "AlphaShield Whale Desk", daily_scans: null },
});

export const SESSION_COOKIE_NAME = "rea_session";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const DEFAULT_INTENT_TTL_MS = 30 * 60 * 1000; // 30 minutes
const MONTHLY_DURATION_MS = 31 * 24 * 60 * 60 * 1000; // 31 days
const YEARLY_DURATION_MS = 366 * 24 * 60 * 60 * 1000; // 366 days

const DUMMY_PASSWORD_HASH = (() => {
  const salt = "00112233445566778899aabbccddeeff";
  return `${salt}:${scryptSync("dummy-constant-time-guard", salt, 64).toString("hex")}`;
})();

function currentBillingMonth() {
  return new Date().toISOString().slice(0, 7);
}

function currentUtcDay() {
  return new Date().toISOString().slice(0, 10);
}

export function sha256Hex(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

function maskSecretToken(token) {
  const str = String(token || "");
  if (str.length <= 16) return "rea_sk_****";
  return `${str.slice(0, 14)}…${str.slice(-4)}`;
}

function hashPassword(password, saltHex = randomBytes(16).toString("hex")) {
  const derived = scryptSync(String(password), saltHex, 64).toString("hex");
  return `${saltHex}:${derived}`;
}

function verifyPassword(password, stored) {
  const [saltHex, expectedHex] = String(stored || "").split(":");
  if (!saltHex || !expectedHex) return false;
  const candidate = Buffer.from(scryptSync(String(password), saltHex, 64).toString("hex"), "hex");
  const expected = Buffer.from(expectedHex, "hex");
  if (candidate.length === 0 || candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

export function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader || typeof cookieHeader !== "string") return out;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k && !(k in out)) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

function shouldUseSecureCookie() {
  if (process.env.NODE_ENV === "production") return true;
  if (String(process.env.REA_INSECURE_HTTP_DEV_COOKIES || "").toLowerCase() === "true") {
    return false;
  }
  return true;
}

export function buildSessionSetCookie(sessionToken, maxAgeSec) {
  const securePart = shouldUseSecureCookie() ? " Secure;" : "";
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionToken)}; HttpOnly;${securePart} SameSite=Lax; Path=/; Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`;
}

export function buildClearSessionCookie() {
  const securePart = shouldUseSecureCookie() ? " Secure;" : "";
  return `${SESSION_COOKIE_NAME}=; HttpOnly;${securePart} SameSite=Lax; Path=/; Max-Age=0`;
}

function tightenFilePermissions(filePath) {
  for (const suffix of ["", "-wal", "-shm"]) {
    const candidate = `${filePath}${suffix}`;
    if (existsSync(candidate)) {
      try {
        chmodSync(candidate, 0o600);
      } catch {
        // Ignore on filesystems without POSIX mode bits
      }
    }
  }
}

/**
 * Transactional SQLite WAL Multi-Tenant Auth, Session, Hashed API Key,
 * License Ownership, Payment-Intent & Replay-Protected Billing Store.
 */
export class TenantBillingStore {
  constructor(storeFilePath, options = {}) {
    this.legacyJsonPath = storeFilePath;
    this.dataDir = dirname(storeFilePath);
    this.sqlitePath = options.sqlitePath || join(this.dataDir, "studio.sqlite");
    this.bootstrapApiKey = String(options.bootstrapApiKey || "").trim() || null;
    this.stripeSecretKey = String(options.stripeSecretKey ?? process.env.STRIPE_SECRET_KEY ?? "").trim();
    this.stripeWebhookSecret = String(
      options.stripeWebhookSecret ?? process.env.STRIPE_WEBHOOK_SECRET ?? "",
    ).trim();
    this.sessionTtlMs = Number(
      options.sessionTtlMs || process.env.STUDIO_SESSION_TTL_MS || DEFAULT_SESSION_TTL_MS,
    );
    this.intentTtlMs = Number(
      options.intentTtlMs || process.env.ALPHASHIELD_INTENT_TTL_MS || DEFAULT_INTENT_TTL_MS,
    );

    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(this.sqlitePath);
    this.initSchema();
    this.migrateLegacyJsonIfNeeded();
    this.ensureBootstrapServiceAccount();
    tightenFilePermissions(this.sqlitePath);
  }

  initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        org_name TEXT NOT NULL,
        password_hash TEXT,
        login_disabled INTEGER NOT NULL DEFAULT 0,
        plan_id TEXT NOT NULL DEFAULT 'free_trial',
        plan_expires_at TEXT,
        alphashield_plan_id TEXT NOT NULL DEFAULT 'free_trial',
        alphashield_expires_at TEXT,
        alphashield_day TEXT NOT NULL,
        alphashield_scans_today INTEGER NOT NULL DEFAULT 0,
        billing_month TEXT NOT NULL,
        scans_used INTEGER NOT NULL DEFAULT 0,
        rl_builds_used INTEGER NOT NULL DEFAULT 0,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        kelviq_studio_subscription_id TEXT,
        kelviq_alphashield_subscription_id TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        token_sha256 TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        prefix TEXT NOT NULL,
        token_sha256 TEXT NOT NULL UNIQUE,
        calls INTEGER NOT NULL DEFAULT 0,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

      CREATE TABLE IF NOT EXISTS billing_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        product TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        amount_usd REAL NOT NULL DEFAULT 0,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_billing_events_tenant ON billing_events(tenant_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS processed_webhook_ids (
        webhook_key TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS consumed_tx_hashes (
        tx_key TEXT PRIMARY KEY,
        chain TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        intent_id TEXT,
        plan_id TEXT NOT NULL,
        expected_usd REAL NOT NULL DEFAULT 0,
        recorded_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS payment_intents (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        chain TEXT NOT NULL,
        payer_wallet TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        charge_period TEXT NOT NULL,
        expected_usd REAL NOT NULL,
        exact_raw_units TEXT NOT NULL,
        display_amount TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        tx_hash TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_payment_intents_lookup ON payment_intents(chain, exact_raw_units, status);

      CREATE TABLE IF NOT EXISTS license_activations (
        license_sha256 TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        product TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        instance_id TEXT,
        expires_at TEXT,
        activated_at TEXT NOT NULL
      );
    `);
  }

  withImmediateTx(fn) {
    if ((this._txDepth || 0) > 0) {
      this._txDepth += 1;
      try {
        return fn();
      } finally {
        this._txDepth -= 1;
      }
    }
    this._txDepth = 1;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // Already rolled back by SQLite
      }
      throw err;
    } finally {
      this._txDepth = 0;
    }
  }

  isSandboxBillingAllowed({ kelviqConfigured = false } = {}) {
    return (
      process.env.ALLOW_SANDBOX_BILLING === "true" &&
      process.env.NODE_ENV !== "production" &&
      !this.stripeSecretKey &&
      !kelviqConfigured
    );
  }

  migrateLegacyJsonIfNeeded() {
    if (!existsSync(this.legacyJsonPath)) return;
    const alreadyMigrated = this.db
      .prepare("SELECT value FROM meta WHERE key = 'legacy_json_migrated'")
      .get();
    if (alreadyMigrated) {
      tightenFilePermissions(this.legacyJsonPath);
      return;
    }

    let parsed = null;
    try {
      parsed = JSON.parse(readFileSync(this.legacyJsonPath, "utf8"));
    } catch {
      parsed = null;
    }

    this.withImmediateTx(() => {
      if (parsed && typeof parsed === "object" && parsed.tenants) {
        const legacyApiKeys = { ...(parsed.api_keys || {}) };

        for (const [tid, t] of Object.entries(parsed.tenants)) {
          if (!t || typeof t !== "object" || tid === "ten_founder_demo") continue;
          if (Array.isArray(t.api_keys)) {
            for (const lk of t.api_keys) {
              if (lk && typeof lk === "object") {
                const lid = lk.id || `key_${randomBytes(6).toString("hex")}`;
                legacyApiKeys[lid] = { ...lk, id: lid, tenant_id: tid };
              }
            }
          }

          let passHash = t.password_hash || null;
          if (t.password_salt && t.password_hash && !String(t.password_hash).includes(":")) {
            passHash = `${t.password_salt}:${t.password_hash}`;
          }

          this.db
            .prepare(
              `INSERT OR IGNORE INTO tenants (
                id, email, org_name, password_hash, login_disabled, plan_id, plan_expires_at,
                alphashield_plan_id, alphashield_expires_at, alphashield_day, alphashield_scans_today,
                billing_month, scans_used, rl_builds_used, stripe_customer_id, stripe_subscription_id,
                kelviq_studio_subscription_id, kelviq_alphashield_subscription_id, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              tid,
              String(t.email || `${tid}@migrated.local`).toLowerCase(),
              String(t.org_name || "Workspace").slice(0, 80),
              passHash,
              t.login_disabled ? 1 : 0,
              PLANS[t.plan_id] ? t.plan_id : "free_trial",
              t.plan_expires_at || null,
              ALPHASHIELD_ENTITLEMENT_PLANS[t.alphashield_plan_id] ? t.alphashield_plan_id : "free_trial",
              t.alphashield_expires_at || null,
              t.alphashield_day || currentUtcDay(),
              Number(t.alphashield_scans_today || 0),
              t.billing_month || currentBillingMonth(),
              Number(t.scans_used || 0),
              Number(t.rl_builds_used || 0),
              t.stripe_customer_id || null,
              t.stripe_subscription_id || null,
              t.kelviq_studio_subscription_id || null,
              t.kelviq_alphashield_subscription_id || null,
              t.created_at || new Date().toISOString(),
            );
        }

        for (const [mapKey, rec] of Object.entries(legacyApiKeys)) {
          if (!rec || typeof rec !== "object" || rec.tenant_id === "ten_founder_demo") continue;
          const ownerExists = this.db.prepare("SELECT 1 FROM tenants WHERE id = ?").get(rec.tenant_id);
          if (!ownerExists) continue;
          const keyId = rec.id || `key_${randomBytes(6).toString("hex")}`;
          let tokenSha = rec.token_sha256 || null;
          let prefix = rec.prefix || null;
          if (!tokenSha && typeof rec.token === "string" && rec.token.length > 0) {
            tokenSha = sha256Hex(rec.token);
            prefix = maskSecretToken(rec.token);
          } else if (!tokenSha && mapKey.startsWith("rea_sk_")) {
            tokenSha = sha256Hex(mapKey);
            prefix = maskSecretToken(mapKey);
          }
          if (!tokenSha) continue;

          this.db
            .prepare(
              `INSERT OR IGNORE INTO api_keys (id, tenant_id, name, prefix, token_sha256, calls, revoked, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              keyId,
              rec.tenant_id,
              String(rec.name || "API Key").slice(0, 64),
              prefix || "rea_sk_****",
              tokenSha,
              Number(rec.calls || 0),
              rec.revoked ? 1 : 0,
              rec.created_at || new Date().toISOString(),
            );
        }

        const nowMs = Date.now();
        for (const [sessKey, sess] of Object.entries(parsed.sessions || {})) {
          if (!sess || sess.tenant_id === "ten_founder_demo") continue;
          const ownerExists = this.db.prepare("SELECT 1 FROM tenants WHERE id = ?").get(sess.tenant_id);
          if (!ownerExists) continue;
          const expiresAt = sess.expires_at || new Date(nowMs + this.sessionTtlMs).toISOString();
          if (Date.parse(expiresAt) <= nowMs) continue;
          const sessSha =
            sess.token_sha256 || (sessKey.startsWith("rea_sess_") ? sha256Hex(sessKey) : sessKey);
          this.db
            .prepare(
              `INSERT OR IGNORE INTO sessions (token_sha256, tenant_id, csrf_token, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)`,
            )
            .run(
              sessSha,
              sess.tenant_id,
              sess.csrf_token || randomBytes(16).toString("hex"),
              sess.created_at || new Date(nowMs).toISOString(),
              expiresAt,
            );
        }

        for (const [whKey, ts] of Object.entries(parsed.processed_webhook_ids || {})) {
          const provider = whKey.includes(":") ? whKey.split(":")[0] : "unknown";
          this.db
            .prepare(
              `INSERT OR IGNORE INTO processed_webhook_ids (webhook_key, provider, recorded_at) VALUES (?, ?, ?)`,
            )
            .run(whKey, provider, String(ts || new Date().toISOString()));
        }

        for (const [txKey, meta] of Object.entries(parsed.consumed_tx_hashes || {})) {
          const [chain, txHash] = txKey.includes(":") ? txKey.split(":") : ["bsc", txKey];
          this.db
            .prepare(
              `INSERT OR IGNORE INTO consumed_tx_hashes (
                tx_key, chain, tx_hash, tenant_id, intent_id, plan_id, expected_usd, recorded_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              txKey,
              chain,
              txHash,
              meta?.tenant_id || "migrated",
              meta?.intent_id || null,
              meta?.plan_id || "alphashield_pro",
              Number(meta?.expected_usd || 0),
              meta?.recorded_at || new Date().toISOString(),
            );
        }
      }

      this.db
        .prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('legacy_json_migrated', ?)")
        .run(new Date().toISOString());
    });

    // Overwrite legacy JSON file with a redacted stub (0600) so zero plaintext secrets or ten_founder_demo remain on disk
    const redactedStub = {
      migrated_to_sqlite: "studio.sqlite",
      migrated_at: new Date().toISOString(),
    };
    const tmp = `${this.legacyJsonPath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(redactedStub, null, 2), { mode: 0o600 });
    renameSync(tmp, this.legacyJsonPath);
    tightenFilePermissions(this.legacyJsonPath);
  }

  ensureBootstrapServiceAccount() {
    if (!this.bootstrapApiKey) return;
    if (this.bootstrapApiKey.length < 20) {
      throw new Error("REA_BOOTSTRAP_API_KEY must be at least 20 characters when set.");
    }
    const bootTenantId = "ten_bootstrap";
    const now = new Date().toISOString();
    const bootPlanId = PLANS[process.env.REA_BOOTSTRAP_PLAN_ID]
      ? process.env.REA_BOOTSTRAP_PLAN_ID
      : "team";
    const bootHash = sha256Hex(this.bootstrapApiKey);

    this.withImmediateTx(() => {
      this.db
        .prepare(
          `INSERT OR IGNORE INTO tenants (
            id, email, org_name, password_hash, login_disabled, plan_id, plan_expires_at,
            alphashield_plan_id, alphashield_expires_at, alphashield_day, alphashield_scans_today,
            billing_month, scans_used, rl_builds_used, created_at
          ) VALUES (?, ?, ?, NULL, 1, ?, NULL, 'free_trial', NULL, ?, 0, ?, 0, 0, ?)`,
        )
        .run(
          bootTenantId,
          "ci-bootstrap@internal.invalid",
          "CI/CD Bootstrap Service Account",
          bootPlanId,
          currentUtcDay(),
          currentBillingMonth(),
          now,
        );

      const existing = this.db.prepare("SELECT * FROM api_keys WHERE id = 'key_bootstrap'").get();
      if (!existing) {
        this.db
          .prepare(
            `INSERT INTO api_keys (id, tenant_id, name, prefix, token_sha256, calls, revoked, created_at)
             VALUES ('key_bootstrap', ?, 'Environment Bootstrap API Key', ?, ?, 0, 0, ?)`,
          )
          .run(bootTenantId, maskSecretToken(this.bootstrapApiKey), bootHash, now);
      } else if (existing.token_sha256 !== bootHash) {
        this.db
          .prepare(
            `UPDATE api_keys SET prefix = ?, token_sha256 = ?, revoked = 0 WHERE id = 'key_bootstrap'`,
          )
          .run(maskSecretToken(this.bootstrapApiKey), bootHash);
      }
    });
  }

  getTenantById(tenantId) {
    if (!tenantId) return null;
    const row = this.db.prepare("SELECT * FROM tenants WHERE id = ?").get(String(tenantId));
    return row ? this.normalizeAndRefreshTenantRow(row) : null;
  }

  normalizeAndRefreshTenantRow(row) {
    if (!row) return null;
    const nowMs = Date.now();
    const month = currentBillingMonth();
    const day = currentUtcDay();

    let planId = PLANS[row.plan_id] ? row.plan_id : "free_trial";
    let planExpiresAt = row.plan_expires_at || null;
    let alphaPlanId = ALPHASHIELD_ENTITLEMENT_PLANS[row.alphashield_plan_id]
      ? row.alphashield_plan_id
      : "free_trial";
    let alphaExpiresAt = row.alphashield_expires_at || null;
    let billingMonth = row.billing_month;
    let scansUsed = Number(row.scans_used || 0);
    let rlBuildsUsed = Number(row.rl_builds_used || 0);
    let alphaDay = row.alphashield_day;
    let alphaScansToday = Number(row.alphashield_scans_today || 0);

    let changed = false;

    // Enforce Studio entitlement expiration on EVERY check
    if (planId !== "free_trial" && planExpiresAt && Date.parse(planExpiresAt) <= nowMs) {
      planId = "free_trial";
      planExpiresAt = null;
      changed = true;
    }

    // Enforce AlphaShield entitlement expiration on EVERY check
    if (alphaPlanId !== "free_trial" && alphaExpiresAt && Date.parse(alphaExpiresAt) <= nowMs) {
      alphaPlanId = "free_trial";
      alphaExpiresAt = null;
      changed = true;
    }

    if (billingMonth !== month) {
      billingMonth = month;
      scansUsed = 0;
      rlBuildsUsed = 0;
      changed = true;
    }
    if (alphaDay !== day) {
      alphaDay = day;
      alphaScansToday = 0;
      changed = true;
    }

    if (changed) {
      this.db
        .prepare(
          `UPDATE tenants
           SET plan_id = ?, plan_expires_at = ?, alphashield_plan_id = ?, alphashield_expires_at = ?,
               billing_month = ?, scans_used = ?, rl_builds_used = ?,
               alphashield_day = ?, alphashield_scans_today = ?
           WHERE id = ?`,
        )
        .run(
          planId,
          planExpiresAt,
          alphaPlanId,
          alphaExpiresAt,
          billingMonth,
          scansUsed,
          rlBuildsUsed,
          alphaDay,
          alphaScansToday,
          row.id,
        );
    }

    return {
      ...row,
      login_disabled: Boolean(row.login_disabled),
      plan_id: planId,
      plan_expires_at: planExpiresAt,
      alphashield_plan_id: alphaPlanId,
      alphashield_expires_at: alphaExpiresAt,
      billing_month: billingMonth,
      scans_used: scansUsed,
      rl_builds_used: rlBuildsUsed,
      alphashield_day: alphaDay,
      alphashield_scans_today: alphaScansToday,
    };
  }

  sanitizeTenant(tenantInput, { kelviqConfigured = false } = {}) {
    if (!tenantInput) return null;
    const tenant = this.getTenantById(tenantInput.id) || tenantInput;
    const plan = PLANS[tenant.plan_id] || PLANS.free_trial;
    const alphaPlan =
      ALPHASHIELD_ENTITLEMENT_PLANS[tenant.alphashield_plan_id] ||
      ALPHASHIELD_ENTITLEMENT_PLANS.free_trial;

    return {
      id: tenant.id,
      email: tenant.email,
      org_name: tenant.org_name,
      plan_id: plan.id,
      plan_name: plan.name,
      plan_badge: plan.badge,
      plan_expires_at: tenant.plan_expires_at || null,
      price_monthly_usd: plan.price_monthly_usd,
      alphashield_plan_id: alphaPlan.id,
      alphashield_plan_name: alphaPlan.name,
      alphashield_expires_at: tenant.alphashield_expires_at || null,
      billing_month: tenant.billing_month,
      usage: {
        scans_used: tenant.scans_used,
        scan_limit: plan.scan_limit,
        rl_builds_used: tenant.rl_builds_used,
        rl_build_limit: plan.rl_build_limit,
        alphashield_scans_today: tenant.alphashield_scans_today || 0,
        alphashield_daily_limit: alphaPlan.daily_scans,
      },
      stripe_mode: this.stripeSecretKey
        ? "live_stripe"
        : this.isSandboxBillingAllowed({ kelviqConfigured })
          ? "sandbox_checkout"
          : "unconfigured",
      created_at: tenant.created_at,
    };
  }

  pruneExpiredArtifacts() {
    const nowIso = new Date().toISOString();
    this.withImmediateTx(() => {
      this.db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowIso);
      this.db
        .prepare("UPDATE payment_intents SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?")
        .run(nowIso);
    });
  }

  issueSessionInTx(tenantId) {
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const expiresIso = new Date(nowMs + this.sessionTtlMs).toISOString();

    this.db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowIso);

    // Cap concurrent active sessions per tenant to 10 (evict oldest)
    const existing = this.db
      .prepare("SELECT token_sha256 FROM sessions WHERE tenant_id = ? ORDER BY created_at ASC")
      .all(tenantId);
    if (existing.length >= 10) {
      for (const old of existing.slice(0, existing.length - 9)) {
        this.db.prepare("DELETE FROM sessions WHERE token_sha256 = ?").run(old.token_sha256);
      }
    }

    const sessionToken = `rea_sess_${randomBytes(24).toString("hex")}`;
    const csrfToken = randomBytes(20).toString("hex");
    const tokenSha = sha256Hex(sessionToken);

    this.db
      .prepare(
        `INSERT INTO sessions (token_sha256, tenant_id, csrf_token, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(tokenSha, tenantId, csrfToken, nowIso, expiresIso);

    return {
      sessionToken,
      csrfToken,
      maxAgeSec: Math.floor(this.sessionTtlMs / 1000),
      expiresAt: expiresIso,
    };
  }

  // -------------------------------------------------------------------------
  // Auth: Register, Login, Logout & Cookie + CSRF Session Resolution
  // -------------------------------------------------------------------------
  register({ email, password, org_name }) {
    const cleanEmail = String(email ?? "").trim().toLowerCase();
    if (!cleanEmail || cleanEmail.length > 254 || !EMAIL_RE.test(cleanEmail)) {
      return { ok: false, error: { code: "invalid_email", message: "Valid work email is required." } };
    }
    const rawPass = String(password ?? "");
    if (rawPass.length < 8 || rawPass.length > 256) {
      return {
        ok: false,
        error: { code: "weak_password", message: "Password must be between 8 and 256 characters." },
      };
    }

    const passHash = hashPassword(rawPass);
    const tenantId = `ten_${randomBytes(8).toString("hex")}`;
    const now = new Date().toISOString();
    const orgName = String(org_name || cleanEmail.split("@")[0]).trim().slice(0, 80) || "Workspace";
    const rawKeyToken = `rea_sk_live_${randomBytes(18).toString("hex")}`;
    const keyId = `key_${randomBytes(6).toString("hex")}`;
    const keyPrefix = maskSecretToken(rawKeyToken);
    const keyHash = sha256Hex(rawKeyToken);

    return this.withImmediateTx(() => {
      const existing = this.db.prepare("SELECT id FROM tenants WHERE email = ?").get(cleanEmail);
      if (existing) {
        return {
          ok: false,
          error: { code: "email_taken", message: "An account with this email already exists." },
        };
      }

      this.db
        .prepare(
          `INSERT INTO tenants (
            id, email, org_name, password_hash, login_disabled, plan_id, plan_expires_at,
            alphashield_plan_id, alphashield_expires_at, alphashield_day, alphashield_scans_today,
            billing_month, scans_used, rl_builds_used, created_at
          ) VALUES (?, ?, ?, ?, 0, 'free_trial', NULL, 'free_trial', NULL, ?, 0, ?, 0, 0, ?)`,
        )
        .run(tenantId, cleanEmail, orgName, passHash, currentUtcDay(), currentBillingMonth(), now);

      this.db
        .prepare(
          `INSERT INTO api_keys (id, tenant_id, name, prefix, token_sha256, calls, revoked, created_at)
           VALUES (?, ?, 'Starter API Key', ?, ?, 0, 0, ?)`,
        )
        .run(keyId, tenantId, keyPrefix, keyHash, now);

      const sess = this.issueSessionInTx(tenantId);
      const tenant = this.getTenantById(tenantId);

      return {
        ok: true,
        _cookie_session_token: sess.sessionToken,
        _cookie_max_age_sec: sess.maxAgeSec,
        csrf_token: sess.csrfToken,
        tenant: this.sanitizeTenant(tenant),
        starter_api_key: {
          id: keyId,
          name: "Starter API Key",
          prefix: keyPrefix,
          secret_token: rawKeyToken,
          created_at: now,
        },
        api_keys: this.listTenantKeys(tenantId),
      };
    });
  }

  login({ email, password }) {
    const cleanEmail = String(email ?? "").trim().toLowerCase();
    const rawPass = String(password ?? "");
    const row = this.db.prepare("SELECT * FROM tenants WHERE email = ?").get(cleanEmail);

    if (!row || row.login_disabled || !row.password_hash) {
      verifyPassword(rawPass, DUMMY_PASSWORD_HASH);
      return { ok: false, error: { code: "invalid_credentials", message: "Invalid email or password." } };
    }
    if (!verifyPassword(rawPass, row.password_hash)) {
      return { ok: false, error: { code: "invalid_credentials", message: "Invalid email or password." } };
    }

    return this.withImmediateTx(() => {
      const sess = this.issueSessionInTx(row.id);
      const tenant = this.normalizeAndRefreshTenantRow(row);
      return {
        ok: true,
        _cookie_session_token: sess.sessionToken,
        _cookie_max_age_sec: sess.maxAgeSec,
        csrf_token: sess.csrfToken,
        tenant: this.sanitizeTenant(tenant),
        api_keys: this.listTenantKeys(row.id),
      };
    });
  }

  extractSessionTokenFromRequest(req) {
    const cookies = parseCookies(req.headers.cookie || "");
    const cookieTok = String(cookies[SESSION_COOKIE_NAME] || "").trim();
    if (cookieTok) return { token: cookieTok, viaCookie: true };
    return { token: "", viaCookie: false };
  }

  resolveSessionContext(req) {
    const { token } = this.extractSessionTokenFromRequest(req);
    if (!token || token.length < 16) return null;

    const sessSha = sha256Hex(token);
    const sess = this.db.prepare("SELECT * FROM sessions WHERE token_sha256 = ?").get(sessSha);
    if (!sess) return null;

    if (!sess.expires_at || Date.parse(sess.expires_at) <= Date.now()) {
      this.db.prepare("DELETE FROM sessions WHERE token_sha256 = ?").run(sessSha);
      return null;
    }

    const tenant = this.getTenantById(sess.tenant_id);
    if (!tenant) {
      this.db.prepare("DELETE FROM sessions WHERE token_sha256 = ?").run(sessSha);
      return null;
    }

    return {
      tenant,
      csrfToken: sess.csrf_token,
      sessionSha256: sessSha,
      expiresAt: sess.expires_at,
    };
  }

  verifyCsrfToken(sessionCtx, req) {
    if (!sessionCtx?.csrfToken) return false;
    const headerToken = String(req.headers["x-csrf-token"] || "").trim();
    if (!headerToken) return false;
    const expected = Buffer.from(sessionCtx.csrfToken, "utf8");
    const provided = Buffer.from(headerToken, "utf8");
    if (expected.length === 0 || expected.length !== provided.length) return false;
    return timingSafeEqual(expected, provided);
  }

  resolveAuthenticatedTenant(req) {
    const ctx = this.resolveSessionContext(req);
    return ctx ? ctx.tenant : null;
  }

  logout(req) {
    const { token } = this.extractSessionTokenFromRequest(req);
    if (!token) return { ok: true, revoked: false };
    const sessSha = sha256Hex(token);
    const info = this.db.prepare("DELETE FROM sessions WHERE token_sha256 = ?").run(sessSha);
    return { ok: true, revoked: info.changes > 0 };
  }

  authenticateApiKey(req) {
    const auth = String(req.headers.authorization || "");
    if (!/^Bearer\s+/i.test(auth)) return null;
    const token = auth.replace(/^Bearer\s+/i, "").trim();
    if (!token || token.length < 16) return null;

    const candidateHex = sha256Hex(token);
    const candidateBuf = Buffer.from(candidateHex, "hex");

    const row = this.db
      .prepare("SELECT * FROM api_keys WHERE token_sha256 = ? AND revoked = 0")
      .get(candidateHex);
    if (!row) return null;

    const storedBuf = Buffer.from(row.token_sha256, "hex");
    if (storedBuf.length !== candidateBuf.length || !timingSafeEqual(storedBuf, candidateBuf)) {
      return null;
    }

    return this.withImmediateTx(() => {
      const freshKey = this.db
        .prepare("SELECT * FROM api_keys WHERE id = ? AND revoked = 0")
        .get(row.id);
      if (!freshKey) return null;
      const tenant = this.getTenantById(freshKey.tenant_id);
      if (!tenant) return null;

      const nextCalls = Number(freshKey.calls || 0) + 1;
      this.db.prepare("UPDATE api_keys SET calls = ? WHERE id = ?").run(nextCalls, freshKey.id);

      return {
        keyRec: {
          id: freshKey.id,
          tenant_id: freshKey.tenant_id,
          name: freshKey.name,
          prefix: freshKey.prefix,
          calls: nextCalls,
          created_at: freshKey.created_at,
        },
        tenant,
      };
    });
  }

  // -------------------------------------------------------------------------
  // API Key Management (Per-Tenant, Masked Metadata Only)
  // -------------------------------------------------------------------------
  listTenantKeys(tenantId) {
    if (!tenantId) return [];
    return this.db
      .prepare(
        `SELECT id, tenant_id, name, prefix, calls, created_at
         FROM api_keys
         WHERE tenant_id = ? AND revoked = 0
         ORDER BY created_at ASC`,
      )
      .all(String(tenantId));
  }

  listTenantBillingEvents(tenantId, limit = 50) {
    if (!tenantId) return [];
    return this.db
      .prepare(
        `SELECT id, tenant_id, product, plan_id, amount_usd, source, created_at
         FROM billing_events
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT ?`,
      )
      .all(String(tenantId), Math.min(200, Math.max(1, Number(limit || 50))));
  }

  createApiKey(tenantId, label) {
    return this.withImmediateTx(() => {
      const tenant = this.getTenantById(tenantId);
      if (!tenant) return { ok: false, status: 401, error: { message: "Workspace not found" } };
      const plan = PLANS[tenant.plan_id] || PLANS.free_trial;
      const activeKeys = this.listTenantKeys(tenantId);
      if (activeKeys.length >= plan.max_api_keys) {
        return {
          ok: false,
          status: 402,
          error: {
            code: "key_limit_reached",
            message: `${plan.name} allows up to ${plan.max_api_keys} active API keys. Upgrade your plan to issue more keys.`,
          },
        };
      }

      const rawToken = `rea_sk_live_${randomBytes(18).toString("hex")}`;
      const keyId = `key_${randomBytes(6).toString("hex")}`;
      const now = new Date().toISOString();
      const name = String(label || "CI/CD Pipeline Key").trim().slice(0, 64) || "CI/CD Pipeline Key";
      const prefix = maskSecretToken(rawToken);
      const tokenHash = sha256Hex(rawToken);

      this.db
        .prepare(
          `INSERT INTO api_keys (id, tenant_id, name, prefix, token_sha256, calls, revoked, created_at)
           VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
        )
        .run(keyId, tenantId, name, prefix, tokenHash, now);

      return {
        ok: true,
        key: {
          id: keyId,
          name,
          prefix,
          secret_token: rawToken,
          calls: 0,
          created_at: now,
        },
        api_keys: this.listTenantKeys(tenantId),
      };
    });
  }

  revokeApiKey(tenantId, keyId) {
    if (!tenantId || !keyId) return { ok: false, error: { message: "Key not found" } };
    return this.withImmediateTx(() => {
      const res = this.db
        .prepare("UPDATE api_keys SET revoked = 1 WHERE tenant_id = ? AND id = ? AND revoked = 0")
        .run(String(tenantId), String(keyId));
      if (res.changes === 0) return { ok: false, error: { message: "Key not found" } };
      return { ok: true, api_keys: this.listTenantKeys(tenantId) };
    });
  }

  // -------------------------------------------------------------------------
  // Atomic Quota Metering, Enforcement & Safe Rollback
  // -------------------------------------------------------------------------
  checkAndConsumeQuota(tenantInput, kind = "scan", units = 1) {
    if (!tenantInput?.id) {
      return { ok: false, status: 401, error: { code: "unauthorized", message: "Authentication required." } };
    }
    const count = Math.max(1, Number(units || 1));

    return this.withImmediateTx(() => {
      const tenant = this.getTenantById(tenantInput.id);
      if (!tenant) {
        return { ok: false, status: 401, error: { code: "unauthorized", message: "Workspace not found." } };
      }
      const plan = PLANS[tenant.plan_id] || PLANS.free_trial;

      if (kind === "rl_build") {
        if (plan.rl_build_limit !== null && tenant.rl_builds_used + count > plan.rl_build_limit) {
          return {
            ok: false,
            status: 402,
            error: {
              code: "quota_exceeded",
              quota_kind: "rl_build",
              plan_id: plan.id,
              used: tenant.rl_builds_used,
              limit: plan.rl_build_limit,
              message: `Monthly RL Factory limit reached (${tenant.rl_builds_used}/${plan.rl_build_limit} on ${plan.name}). Upgrade to ShipGate Team ($299/mo) or AI Lab ($1,499/mo) to continue building AgentEnvs.`,
            },
          };
        }
        this.db
          .prepare("UPDATE tenants SET rl_builds_used = rl_builds_used + ? WHERE id = ?")
          .run(count, tenant.id);
        return { ok: true, tenant: this.sanitizeTenant(this.getTenantById(tenant.id)) };
      }

      if (plan.scan_limit !== null && tenant.scans_used + count > plan.scan_limit) {
        return {
          ok: false,
          status: 402,
          error: {
            code: "quota_exceeded",
            quota_kind: "scan",
            plan_id: plan.id,
            used: tenant.scans_used,
            limit: plan.scan_limit,
            message: `Monthly scan quota reached (${tenant.scans_used}/${plan.scan_limit} on ${plan.name}). Upgrade your plan to unlock additional AppScope & ShipGate scans.`,
          },
        };
      }

      this.db
        .prepare("UPDATE tenants SET scans_used = scans_used + ? WHERE id = ?")
        .run(count, tenant.id);
      return { ok: true, tenant: this.sanitizeTenant(this.getTenantById(tenant.id)) };
    });
  }

  refundQuota(tenantId, kind = "scan", units = 1) {
    if (!tenantId) return;
    const count = Math.max(1, Number(units || 1));
    this.withImmediateTx(() => {
      if (kind === "rl_build") {
        this.db
          .prepare("UPDATE tenants SET rl_builds_used = MAX(0, rl_builds_used - ?) WHERE id = ?")
          .run(count, String(tenantId));
      } else {
        this.db
          .prepare("UPDATE tenants SET scans_used = MAX(0, scans_used - ?) WHERE id = ?")
          .run(count, String(tenantId));
      }
    });
  }

  checkAndConsumeAlphaShieldQuota(tenantInput) {
    if (!tenantInput?.id) {
      return { ok: false, status: 401, error: { code: "unauthorized", message: "Authentication required." } };
    }

    return this.withImmediateTx(() => {
      const tenant = this.getTenantById(tenantInput.id);
      if (!tenant) {
        return { ok: false, status: 401, error: { code: "unauthorized", message: "Workspace not found." } };
      }
      const alphaPlan =
        ALPHASHIELD_ENTITLEMENT_PLANS[tenant.alphashield_plan_id] ||
        ALPHASHIELD_ENTITLEMENT_PLANS.free_trial;
      const studioPaid = tenant.plan_id && tenant.plan_id !== "free_trial";

      if (
        !studioPaid &&
        alphaPlan.daily_scans !== null &&
        tenant.alphashield_scans_today >= alphaPlan.daily_scans
      ) {
        return {
          ok: false,
          status: 402,
          error: {
            code: "alphashield_quota_exceeded",
            used: tenant.alphashield_scans_today,
            limit: alphaPlan.daily_scans,
            message: `Daily free AlphaShield limit reached (${tenant.alphashield_scans_today}/${alphaPlan.daily_scans}). Upgrade to AlphaShield Pro to unlock unlimited scans.`,
          },
        };
      }

      this.db
        .prepare("UPDATE tenants SET alphashield_scans_today = alphashield_scans_today + 1 WHERE id = ?")
        .run(tenant.id);
      return { ok: true, tenant: this.sanitizeTenant(this.getTenantById(tenant.id)) };
    });
  }

  refundAlphaShieldQuota(tenantId, units = 1) {
    if (!tenantId) return;
    const count = Math.max(1, Number(units || 1));
    this.withImmediateTx(() => {
      this.db
        .prepare(
          "UPDATE tenants SET alphashield_scans_today = MAX(0, alphashield_scans_today - ?) WHERE id = ?",
        )
        .run(count, String(tenantId));
    });
  }

  backupTo(destBackupPath) {
    return backupSqliteDatabase(this.sqlitePath, destBackupPath);
  }

  // -------------------------------------------------------------------------
  // Webhook Replay, License Anti-Sharing & Bound On-Chain Payment Intents
  // -------------------------------------------------------------------------
  isWebhookProcessed(provider, eventId) {
    if (!eventId) return false;
    const row = this.db
      .prepare("SELECT 1 FROM processed_webhook_ids WHERE webhook_key = ?")
      .get(`${provider}:${eventId}`);
    return Boolean(row);
  }

  markWebhookProcessed(provider, eventId) {
    if (!eventId) return;
    this.db
      .prepare(
        "INSERT OR IGNORE INTO processed_webhook_ids (webhook_key, provider, recorded_at) VALUES (?, ?, ?)",
      )
      .run(`${provider}:${eventId}`, String(provider), new Date().toISOString());
  }

  getLicenseBinding(licenseKey) {
    const hash = sha256Hex(String(licenseKey || "").trim());
    return this.db
      .prepare("SELECT * FROM license_activations WHERE license_sha256 = ?")
      .get(hash) || null;
  }

  bindAndProvisionLicense({ tenantId, licenseKey, product, planId, instanceId, expiresAt }) {
    const hash = sha256Hex(String(licenseKey || "").trim());
    const nowIso = new Date().toISOString();

    return this.withImmediateTx(() => {
      const existing = this.db
        .prepare("SELECT * FROM license_activations WHERE license_sha256 = ?")
        .get(hash);
      if (existing && existing.tenant_id !== tenantId) {
        return {
          ok: false,
          status: 409,
          error: {
            code: "license_already_bound",
            message: "This license key is already bound to another workspace.",
          },
        };
      }

      if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
        return {
          ok: false,
          status: 400,
          error: { code: "license_expired", message: "License key has expired." },
        };
      }

      this.db
        .prepare(
          `INSERT INTO license_activations (
            license_sha256, tenant_id, product, plan_id, instance_id, expires_at, activated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(license_sha256) DO UPDATE SET
            instance_id = excluded.instance_id,
            expires_at = excluded.expires_at,
            activated_at = excluded.activated_at`,
        )
        .run(hash, tenantId, product, planId, instanceId || null, expiresAt || null, nowIso);

      if (product === "studio") {
        return this.applyPlanProvisioning(tenantId, planId, {
          source: "kelviq_license_key",
          expires_at: expiresAt || null,
        });
      }
      return this.applyAlphaShieldProvisioning(tenantId, planId, {
        source: "kelviq_license_key",
        expires_at: expiresAt || null,
      });
    });
  }

  createUsdtPaymentIntent({ tenantId, chain, payerWallet, planId, chargePeriod, baseUsd, decimals }) {
    const cleanWallet = String(payerWallet || "").trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(cleanWallet)) {
      return {
        ok: false,
        status: 400,
        error: {
          code: "invalid_payer_wallet",
          message: "Provide the 42-character 0x wallet address that will send the USDT transfer.",
        },
      };
    }

    return this.withImmediateTx(() => {
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const expiresIso = new Date(nowMs + this.intentTtlMs).toISOString();

      this.db
        .prepare("UPDATE payment_intents SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?")
        .run(nowIso);

      // Generate a unique sub-cent atomic tag (1..9999 = $0.0001..$0.0099) so exact_raw_units is globally unique per active intent
      const dec = BigInt(decimals);
      const baseUnits = BigInt(baseUsd) * 10n ** dec;
      const microStep = dec >= 6n ? 10n ** (dec - 4n) : 1n; // 1 unit = $0.0001

      let exactRawUnits = null;
      let tagNum = 0;
      for (let attempt = 0; attempt < 40; attempt += 1) {
        const candidateTag = (randomBytes(2).readUInt16BE(0) % 9000) + 1000; // 1000..9999 -> +$0.1000..+$0.9999? Wait: 1..99 -> +$0.0001..+$0.0099!
        const subCentTag = (candidateTag % 99) + 1; // 1..99 ($0.0001 .. $0.0099)
        const extraSubMicro = dec >= 6n ? BigInt((randomBytes(2).readUInt16BE(0) % 99) + 1) * (10n ** (dec - 6n)) : 0n;
        const candidateUnits = (baseUnits + BigInt(subCentTag) * microStep + extraSubMicro).toString();

        const clash = this.db
          .prepare(
            "SELECT 1 FROM payment_intents WHERE chain = ? AND exact_raw_units = ? AND status = 'pending'",
          )
          .get(chain, candidateUnits);
        if (!clash) {
          exactRawUnits = candidateUnits;
          tagNum = Number(BigInt(candidateUnits) - baseUnits);
          break;
        }
      }
      if (!exactRawUnits) {
        return {
          ok: false,
          status: 503,
          error: { message: "Could not allocate unique payment intent; retry shortly." },
        };
      }

      const fracStr = (BigInt(exactRawUnits) % 10n ** dec)
        .toString()
        .padStart(Number(dec), "0")
        .replace(/0+$/, "");
      const displayAmount = fracStr ? `${baseUsd}.${fracStr}` : `${baseUsd}`;
      const intentId = `pi_${randomBytes(12).toString("hex")}`;

      this.db
        .prepare(
          `INSERT INTO payment_intents (
            id, tenant_id, chain, payer_wallet, plan_id, charge_period,
            expected_usd, exact_raw_units, display_amount, status, created_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
        )
        .run(
          intentId,
          tenantId,
          chain,
          cleanWallet,
          planId,
          chargePeriod,
          baseUsd,
          exactRawUnits,
          displayAmount,
          nowIso,
          expiresIso,
        );

      return {
        ok: true,
        intent: {
          intent_id: intentId,
          tenant_id: tenantId,
          chain,
          payer_wallet: cleanWallet,
          plan_id: planId,
          charge_period: chargePeriod,
          expected_usd: baseUsd,
          exact_raw_units: exactRawUnits,
          display_amount: displayAmount,
          exact_human_amount: displayAmount,
          atomic_tag: tagNum,
          created_at: nowIso,
          expires_at: expiresIso,
        },
      };
    });
  }

  getPaymentIntent(intentId) {
    if (!intentId) return null;
    return this.db.prepare("SELECT * FROM payment_intents WHERE id = ?").get(String(intentId)) || null;
  }

  isTxHashConsumed(chain, txHash) {
    const key = `${String(chain).toLowerCase()}:${String(txHash).toLowerCase()}`;
    return Boolean(this.db.prepare("SELECT 1 FROM consumed_tx_hashes WHERE tx_key = ?").get(key));
  }

  redeemUsdtPaymentIntent({ intentId, tenantId, chain, txHash, matchedSymbol }) {
    const cleanChain = String(chain).toLowerCase();
    const cleanTx = String(txHash).toLowerCase();
    const txKey = `${cleanChain}:${cleanTx}`;

    return this.withImmediateTx(() => {
      const intent = this.db.prepare("SELECT * FROM payment_intents WHERE id = ?").get(String(intentId));
      if (!intent) {
        return { ok: false, status: 404, error: { code: "intent_not_found", message: "Payment intent not found." } };
      }
      if (intent.tenant_id !== tenantId) {
        return {
          ok: false,
          status: 403,
          error: {
            code: "intent_tenant_mismatch",
            message: "This payment intent belongs to a different account.",
          },
        };
      }
      if (intent.status !== "pending") {
        return {
          ok: false,
          status: 409,
          error: { code: "intent_not_pending", message: `Payment intent is already ${intent.status}.` },
        };
      }
      if (Date.parse(intent.expires_at) <= Date.now()) {
        this.db.prepare("UPDATE payment_intents SET status = 'expired' WHERE id = ?").run(intent.id);
        return {
          ok: false,
          status: 400,
          error: { code: "intent_expired", message: "Payment intent has expired." },
        };
      }

      const alreadyUsed = this.db.prepare("SELECT 1 FROM consumed_tx_hashes WHERE tx_key = ?").get(txKey);
      if (alreadyUsed) {
        return {
          ok: false,
          status: 409,
          error: { code: "tx_already_redeemed", message: "This transaction hash has already been redeemed." },
        };
      }

      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const durationMs = intent.charge_period === "YEARLY" ? YEARLY_DURATION_MS : MONTHLY_DURATION_MS;
      const existingTenant = this.db.prepare("SELECT alphashield_expires_at FROM tenants WHERE id = ?").get(tenantId);
      const existingExpMs = existingTenant?.alphashield_expires_at
        ? Date.parse(existingTenant.alphashield_expires_at)
        : 0;
      const baseMs = Number.isFinite(existingExpMs) && existingExpMs > nowMs ? existingExpMs : nowMs;
      const expiresAt = new Date(baseMs + durationMs).toISOString();

      this.db
        .prepare(
          `INSERT INTO consumed_tx_hashes (
            tx_key, chain, tx_hash, tenant_id, intent_id, plan_id, expected_usd, recorded_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(txKey, cleanChain, cleanTx, tenantId, intent.id, intent.plan_id, intent.expected_usd, nowIso);

      this.db
        .prepare("UPDATE payment_intents SET status = 'redeemed', tx_hash = ? WHERE id = ?")
        .run(cleanTx, intent.id);

      const provisioned = this.applyAlphaShieldProvisioningInTx(tenantId, intent.plan_id, {
        amount_usd: intent.expected_usd,
        expires_at: expiresAt,
        source: `onchain_${cleanChain}_${String(matchedSymbol || "usdt").toLowerCase()}`,
      });

      return {
        ok: true,
        chain: cleanChain,
        token: matchedSymbol,
        plan_id: intent.plan_id,
        expires_at: expiresAt,
        tenant: provisioned.tenant,
      };
    });
  }

  // -------------------------------------------------------------------------
  // Stripe & Kelviq Provisioning + Subscription-Bound Cancellations
  // -------------------------------------------------------------------------
  async createCheckoutSession(tenant, planId, originUrl, { kelviqConfigured = false } = {}) {
    if (!tenant) {
      return { ok: false, status: 401, error: { message: "Sign in to upgrade your workspace plan." } };
    }
    const plan = PLANS[planId];
    if (!plan || plan.unit_amount_cents <= 0) {
      return { ok: false, status: 400, error: { message: "Select a paid Studio plan (indie, team, or ai_lab)." } };
    }

    if (this.stripeSecretKey) {
      const form = new URLSearchParams();
      form.set("mode", "subscription");
      form.set("customer_email", tenant.email);
      form.set("client_reference_id", tenant.id);
      form.set("success_url", `${originUrl}/?billing=return&plan=${encodeURIComponent(plan.id)}`);
      form.set("cancel_url", `${originUrl}/?billing=canceled`);
      form.set("metadata[tenant_id]", tenant.id);
      form.set("metadata[plan_id]", plan.id);
      form.set("subscription_data[metadata][tenant_id]", tenant.id);
      form.set("subscription_data[metadata][plan_id]", plan.id);
      form.set("line_items[0][quantity]", "1");
      form.set("line_items[0][price_data][currency]", "usd");
      form.set("line_items[0][price_data][unit_amount]", String(plan.unit_amount_cents));
      form.set("line_items[0][price_data][recurring][interval]", "month");
      form.set("line_items[0][price_data][product_data][name]", `REA Cloud Studio — ${plan.name}`);

      const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.stripeSecretKey}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: form.toString(),
      });
      const data = await resp.json();
      if (!resp.ok) {
        return {
          ok: false,
          error: { message: data?.error?.message || "Stripe API checkout creation failed" },
        };
      }
      return {
        ok: true,
        mode: "live_stripe",
        checkout_url: data.url,
        session_id: data.id,
      };
    }

    if (!this.isSandboxBillingAllowed({ kelviqConfigured })) {
      return {
        ok: false,
        status: 503,
        error: {
          code: "billing_not_configured",
          message:
            "Live Stripe billing is not configured on this server (sandbox billing requires ALLOW_SANDBOX_BILLING=true in non-production).",
        },
      };
    }

    const sandboxSessionId = `cs_test_${randomBytes(10).toString("hex")}`;
    return {
      ok: true,
      mode: "sandbox_checkout",
      session_id: sandboxSessionId,
      plan: {
        id: plan.id,
        name: plan.name,
        price_monthly_usd: plan.price_monthly_usd,
      },
      tenant: this.sanitizeTenant(tenant, { kelviqConfigured }),
    };
  }

  applyPlanProvisioningInTx(tenantId, planId, meta = {}) {
    const row = this.db.prepare("SELECT * FROM tenants WHERE id = ?").get(String(tenantId));
    const plan = PLANS[planId];
    if (!row || !plan) {
      return { ok: false, status: 400, error: { message: "Unknown tenant or Studio plan" } };
    }

    const nowMs = Date.now();
    const existingExpMs = row.plan_expires_at ? Date.parse(row.plan_expires_at) : 0;
    const baseMs =
      row.plan_id === plan.id && Number.isFinite(existingExpMs) && existingExpMs > nowMs
        ? existingExpMs
        : nowMs;
    const expiresAt =
      plan.id === "free_trial"
        ? null
        : meta.expires_at !== undefined
          ? meta.expires_at
          : new Date(baseMs + MONTHLY_DURATION_MS).toISOString();

    const stripeCust = meta.stripe_customer_id !== undefined ? meta.stripe_customer_id : row.stripe_customer_id;
    const stripeSub =
      plan.id === "free_trial" && String(meta.source || "").startsWith("stripe")
        ? null
        : meta.stripe_subscription_id !== undefined
          ? meta.stripe_subscription_id
          : row.stripe_subscription_id;
    const kvqStudioSub =
      plan.id === "free_trial" && String(meta.source || "").startsWith("kelviq")
        ? null
        : meta.kelviq_subscription_id !== undefined
          ? meta.kelviq_subscription_id
          : row.kelviq_studio_subscription_id;

    this.db
      .prepare(
        `UPDATE tenants
         SET plan_id = ?, plan_expires_at = ?, stripe_customer_id = ?,
             stripe_subscription_id = ?, kelviq_studio_subscription_id = ?
         WHERE id = ?`,
      )
      .run(plan.id, expiresAt, stripeCust || null, stripeSub || null, kvqStudioSub || null, row.id);

    const eventRecord = {
      id: `evt_${randomBytes(6).toString("hex")}`,
      tenant_id: row.id,
      product: "studio",
      plan_id: plan.id,
      amount_usd: plan.price_monthly_usd,
      source: meta.source || "stripe_webhook",
      created_at: new Date().toISOString(),
    };
    this.db
      .prepare(
        `INSERT INTO billing_events (id, tenant_id, product, plan_id, amount_usd, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        eventRecord.id,
        eventRecord.tenant_id,
        eventRecord.product,
        eventRecord.plan_id,
        eventRecord.amount_usd,
        eventRecord.source,
        eventRecord.created_at,
      );

    return {
      ok: true,
      tenant: this.sanitizeTenant(this.getTenantById(row.id)),
      event: eventRecord,
    };
  }

  applyPlanProvisioning(tenantId, planId, meta = {}) {
    return this.withImmediateTx(() => this.applyPlanProvisioningInTx(tenantId, planId, meta));
  }

  applyAlphaShieldProvisioningInTx(tenantId, alphaPlanId, meta = {}) {
    const row = this.db.prepare("SELECT * FROM tenants WHERE id = ?").get(String(tenantId));
    const plan = ALPHASHIELD_ENTITLEMENT_PLANS[alphaPlanId];
    if (!row || !plan) {
      return { ok: false, status: 400, error: { message: "Unknown tenant or AlphaShield plan" } };
    }

    const nowMs = Date.now();
    const existingExpMs = row.alphashield_expires_at ? Date.parse(row.alphashield_expires_at) : 0;
    const baseMs =
      row.alphashield_plan_id === plan.id && Number.isFinite(existingExpMs) && existingExpMs > nowMs
        ? existingExpMs
        : nowMs;
    const expiresAt =
      plan.id === "free_trial"
        ? null
        : meta.expires_at !== undefined
          ? meta.expires_at
          : new Date(baseMs + MONTHLY_DURATION_MS).toISOString();

    const kvqAlphaSub =
      plan.id === "free_trial" && String(meta.source || "").startsWith("kelviq")
        ? null
        : meta.kelviq_subscription_id !== undefined
          ? meta.kelviq_subscription_id
          : row.kelviq_alphashield_subscription_id;

    this.db
      .prepare(
        `UPDATE tenants
         SET alphashield_plan_id = ?, alphashield_expires_at = ?, kelviq_alphashield_subscription_id = ?
         WHERE id = ?`,
      )
      .run(plan.id, expiresAt, kvqAlphaSub || null, row.id);

    const eventRecord = {
      id: `evt_${randomBytes(6).toString("hex")}`,
      tenant_id: row.id,
      product: "alphashield",
      plan_id: plan.id,
      amount_usd: Number(meta.amount_usd ?? 0),
      source: meta.source || "alphashield_billing",
      created_at: new Date().toISOString(),
    };
    this.db
      .prepare(
        `INSERT INTO billing_events (id, tenant_id, product, plan_id, amount_usd, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        eventRecord.id,
        eventRecord.tenant_id,
        eventRecord.product,
        eventRecord.plan_id,
        eventRecord.amount_usd,
        eventRecord.source,
        eventRecord.created_at,
      );

    return {
      ok: true,
      tenant: this.sanitizeTenant(this.getTenantById(row.id)),
      event: eventRecord,
    };
  }

  applyAlphaShieldProvisioning(tenantId, alphaPlanId, meta = {}) {
    return this.withImmediateTx(() =>
      this.applyAlphaShieldProvisioningInTx(tenantId, alphaPlanId, meta),
    );
  }

  handleKelviqTermination({ subscriptionId, tenantId, resolvedEntitlement, source }) {
    return this.withImmediateTx(() => {
      const downgradedProducts = [];

      // 1. Primary lookup: exact stored subscription ID (immune to missing planIdentifier!)
      if (subscriptionId) {
        const studioOwner = this.db
          .prepare("SELECT id FROM tenants WHERE kelviq_studio_subscription_id = ?")
          .get(String(subscriptionId));
        if (studioOwner) {
          this.applyPlanProvisioningInTx(studioOwner.id, "free_trial", { source });
          downgradedProducts.push("studio");
        }
        const alphaOwner = this.db
          .prepare("SELECT id FROM tenants WHERE kelviq_alphashield_subscription_id = ?")
          .get(String(subscriptionId));
        if (alphaOwner) {
          this.applyAlphaShieldProvisioningInTx(alphaOwner.id, "free_trial", { source });
          downgradedProducts.push("alphashield");
        }
      }

      if (downgradedProducts.length > 0) {
        return { ok: true, downgraded_products: downgradedProducts };
      }

      // 2. Fallback when subscriptionId was not matched/present: use tenantId
      if (!tenantId) {
        return { ok: true, downgraded_products: [] };
      }
      const row = this.db.prepare("SELECT * FROM tenants WHERE id = ?").get(String(tenantId));
      if (!row) {
        return { ok: false, status: 404, error: { message: "Tenant not found" } };
      }

      if (resolvedEntitlement?.product === "studio") {
        this.applyPlanProvisioningInTx(row.id, "free_trial", { source });
        downgradedProducts.push("studio");
      } else if (resolvedEntitlement?.product === "alphashield") {
        this.applyAlphaShieldProvisioningInTx(row.id, "free_trial", { source });
        downgradedProducts.push("alphashield");
      } else {
        // Unknown or missing planIdentifier: NEVER assume AlphaShield only!
        // Fail-safe: downgrade any Kelviq-backed (non-Stripe) active Studio plan AND any active AlphaShield plan.
        if (row.plan_id !== "free_trial" && (row.kelviq_studio_subscription_id || !row.stripe_subscription_id)) {
          this.applyPlanProvisioningInTx(row.id, "free_trial", { source });
          downgradedProducts.push("studio");
        }
        if (row.alphashield_plan_id !== "free_trial") {
          this.applyAlphaShieldProvisioningInTx(row.id, "free_trial", { source });
          downgradedProducts.push("alphashield");
        }
      }

      return { ok: true, downgraded_products: downgradedProducts };
    });
  }

  verifyAndHandleStripeWebhook(rawBodyBuffer, signatureHeader) {
    if (!this.stripeWebhookSecret) {
      return { ok: false, status: 400, error: { message: "STRIPE_WEBHOOK_SECRET not configured" } };
    }

    let timestamp = "";
    const v1Signatures = [];
    for (const part of String(signatureHeader || "").split(",")) {
      const eq = part.indexOf("=");
      if (eq <= 0) continue;
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1).trim();
      if (k === "t") timestamp = v;
      else if (k === "v1" && /^[0-9a-fA-F]{64}$/.test(v)) v1Signatures.push(v.toLowerCase());
    }
    if (!timestamp || v1Signatures.length === 0) {
      return { ok: false, status: 400, error: { message: "Malformed Stripe-Signature header" } };
    }

    const ageSec = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
    if (!Number.isFinite(ageSec) || ageSec > 300) {
      return { ok: false, status: 400, error: { message: "Webhook timestamp outside 5-minute tolerance" } };
    }

    const signedPayload = `${timestamp}.${rawBodyBuffer.toString("utf8")}`;
    const expectedBuf = createHmac("sha256", this.stripeWebhookSecret).update(signedPayload).digest();
    const validSig = v1Signatures.some((hexSig) => {
      const providedBuf = Buffer.from(hexSig, "hex");
      return providedBuf.length === expectedBuf.length && timingSafeEqual(expectedBuf, providedBuf);
    });
    if (!validSig) {
      return { ok: false, status: 400, error: { message: "Invalid Stripe webhook signature" } };
    }

    let event;
    try {
      event = JSON.parse(rawBodyBuffer.toString("utf8"));
    } catch {
      return { ok: false, status: 400, error: { message: "Invalid JSON webhook payload" } };
    }

    return this.withImmediateTx(() => {
      if (event.id && this.isWebhookProcessed("stripe", event.id)) {
        return { ok: true, duplicate: true, event_id: event.id };
      }

      let outcome = { ok: true, ignored: event.type };
      if (event.type === "checkout.session.completed") {
        const obj = event.data?.object || {};
        if (
          obj.payment_status &&
          obj.payment_status !== "paid" &&
          obj.payment_status !== "no_payment_required"
        ) {
          return { ok: false, status: 400, error: { message: "Checkout session payment is not settled" } };
        }
        const tenantId = obj.metadata?.tenant_id || obj.client_reference_id;
        const planId = obj.metadata?.plan_id;
        if (!tenantId || !planId || !PLANS[planId] || planId === "free_trial") {
          return {
            ok: false,
            status: 400,
            error: { message: "Missing or invalid tenant_id / plan_id metadata on checkout session" },
          };
        }
        const periodEndSec = Number(obj.expires_at_subscription || 0);
        const expiresAt =
          periodEndSec > 0
            ? new Date(periodEndSec * 1000).toISOString()
            : new Date(Date.now() + MONTHLY_DURATION_MS).toISOString();

        outcome = this.applyPlanProvisioningInTx(tenantId, planId, {
          source: "stripe_webhook",
          stripe_customer_id: obj.customer || null,
          stripe_subscription_id: obj.subscription || null,
          expires_at: expiresAt,
        });
      } else if (event.type === "customer.subscription.deleted") {
        const subId = event.data?.object?.id;
        const row = subId
          ? this.db.prepare("SELECT id FROM tenants WHERE stripe_subscription_id = ?").get(String(subId))
          : null;
        if (row) {
          outcome = this.applyPlanProvisioningInTx(row.id, "free_trial", {
            source: "stripe_subscription_canceled",
          });
        }
      } else if (event.type === "customer.subscription.updated") {
        const obj = event.data?.object || {};
        const subId = obj.id;
        const badStatuses = new Set(["canceled", "unpaid", "incomplete_expired", "past_due"]);
        if (subId && badStatuses.has(String(obj.status || ""))) {
          const row = this.db
            .prepare("SELECT id FROM tenants WHERE stripe_subscription_id = ?")
            .get(String(subId));
          if (row) {
            outcome = this.applyPlanProvisioningInTx(row.id, "free_trial", {
              source: `stripe_subscription_${obj.status}`,
            });
          }
        } else if (subId && obj.current_period_end) {
          const row = this.db
            .prepare("SELECT id FROM tenants WHERE stripe_subscription_id = ?")
            .get(String(subId));
          if (row) {
            this.db
              .prepare("UPDATE tenants SET plan_expires_at = ? WHERE id = ?")
              .run(new Date(Number(obj.current_period_end) * 1000).toISOString(), row.id);
          }
        }
      } else if (event.type === "invoice.payment_failed") {
        const subId = event.data?.object?.subscription;
        const custId = event.data?.object?.customer;
        const row = subId
          ? this.db.prepare("SELECT id FROM tenants WHERE stripe_subscription_id = ?").get(String(subId))
          : custId
            ? this.db.prepare("SELECT id FROM tenants WHERE stripe_customer_id = ?").get(String(custId))
            : null;
        if (row) {
          outcome = this.applyPlanProvisioningInTx(row.id, "free_trial", {
            source: "stripe_invoice_payment_failed",
          });
        }
      }

      if (outcome.ok && event.id) {
        this.markWebhookProcessed("stripe", event.id);
      }
      return outcome;
    });
  }

  pruneExpiredRecords(nowIso = new Date().toISOString()) {
    this.withImmediateTx(() => {
      this.db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowIso);
      this.db
        .prepare("UPDATE payment_intents SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?")
        .run(nowIso);
    });
  }

  close() {
    try {
      this.db.close();
    } catch {
      // already closed
    }
  }
}
