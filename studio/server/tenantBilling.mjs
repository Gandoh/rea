import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

export const PLANS = Object.freeze({
  free_trial: {
    id: "free_trial",
    name: "Free Developer Trial",
    price_monthly_usd: 0,
    unit_amount_cents: 0,
    scan_limit: 5, // 5 scans/mo
    rl_build_limit: 2, // 2 HAR -> AgentEnv builds/mo
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
    scan_limit: null, // Unlimited
    rl_build_limit: 15,
    max_api_keys: 20,
    badge: "$299/mo",
  },
  ai_lab: {
    id: "ai_lab",
    name: "AI Lab RL Factory",
    price_monthly_usd: 1499,
    unit_amount_cents: 149900,
    scan_limit: null, // Unlimited
    rl_build_limit: null, // Unlimited
    max_api_keys: 100,
    badge: "$1,499/mo",
  },
});

function currentBillingMonth() {
  return new Date().toISOString().slice(0, 7); // YYYY-MM
}

function hashPassword(password, saltHex = randomBytes(16).toString("hex")) {
  const derived = scryptSync(String(password), saltHex, 64).toString("hex");
  return `${saltHex}:${derived}`;
}

function verifyPassword(password, stored) {
  const [saltHex, expectedHex] = String(stored || "").split(":");
  if (!saltHex || !expectedHex) return false;
  const candidate = Buffer.from(scryptSync(String(password), saltHex, 64).toString("hex"), "utf8");
  const expected = Buffer.from(expectedHex, "utf8");
  if (candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

/**
 * Persistent Multi-Tenant Auth, API Key, Usage Quota & Stripe Billing Manager.
 */
export class TenantBillingStore {
  constructor(storeFilePath, options = {}) {
    this.storeFilePath = storeFilePath;
    this.bootstrapApiKey = options.bootstrapApiKey || null;
    this.stripeSecretKey = options.stripeSecretKey || process.env.STRIPE_SECRET_KEY || "";
    this.stripeWebhookSecret = options.stripeWebhookSecret || process.env.STRIPE_WEBHOOK_SECRET || "";

    mkdirSync(dirname(this.storeFilePath), { recursive: true });
    this.state = {
      tenants: {},
      sessions: {},
      api_keys: {},
      billing_events: [],
      default_tenant_id: null,
    };
    this.loadOrSeed();
  }

  loadOrSeed() {
    if (existsSync(this.storeFilePath)) {
      try {
        const parsed = JSON.parse(readFileSync(this.storeFilePath, "utf8"));
        if (parsed && typeof parsed === "object" && parsed.tenants) {
          this.state = parsed;
          return;
        }
      } catch {
        // Re-seed if corrupted
      }
    }

    // Seed default workspace so immediate preview works out of the box
    const tenantId = "ten_founder_demo";
    const now = new Date().toISOString();
    this.state.tenants[tenantId] = {
      id: tenantId,
      email: "founder@acme-security.dev",
      org_name: "Acme AppSec Workspace",
      password_hash: hashPassword("demo-password-123"),
      plan_id: "free_trial",
      billing_month: currentBillingMonth(),
      scans_used: 0,
      rl_builds_used: 0,
      stripe_customer_id: null,
      stripe_subscription_id: null,
      created_at: now,
    };
    this.state.default_tenant_id = tenantId;

    const initialToken = this.bootstrapApiKey || `rea_sk_live_${randomBytes(12).toString("hex")}`;
    this.state.api_keys[initialToken] = {
      id: "key_default",
      tenant_id: tenantId,
      name: "Default CI/CD & CLI Key",
      prefix: `${initialToken.slice(0, 18)}…`,
      token: initialToken,
      calls: 0,
      revoked: false,
      created_at: now,
    };

    this.save();
  }

  save() {
    const tmp = `${this.storeFilePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.storeFilePath);
  }

  ensureCurrentBillingPeriod(tenant) {
    const month = currentBillingMonth();
    if (tenant.billing_month !== month) {
      tenant.billing_month = month;
      tenant.scans_used = 0;
      tenant.rl_builds_used = 0;
      this.save();
    }
  }

  sanitizeTenant(tenant) {
    if (!tenant) return null;
    this.ensureCurrentBillingPeriod(tenant);
    const plan = PLANS[tenant.plan_id] || PLANS.free_trial;
    return {
      id: tenant.id,
      email: tenant.email,
      org_name: tenant.org_name,
      plan_id: plan.id,
      plan_name: plan.name,
      plan_badge: plan.badge,
      price_monthly_usd: plan.price_monthly_usd,
      billing_month: tenant.billing_month,
      usage: {
        scans_used: tenant.scans_used,
        scan_limit: plan.scan_limit,
        rl_builds_used: tenant.rl_builds_used,
        rl_build_limit: plan.rl_build_limit,
      },
      stripe_mode: this.stripeSecretKey ? "live_stripe" : "sandbox_checkout",
      created_at: tenant.created_at,
    };
  }

  // -------------------------------------------------------------------------
  // Auth: Register, Login, Session Resolution
  // -------------------------------------------------------------------------
  register({ email, password, org_name }) {
    const cleanEmail = String(email || "").trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes("@")) {
      return { ok: false, error: { code: "invalid_email", message: "Valid email is required." } };
    }
    if (!password || String(password).length < 6) {
      return { ok: false, error: { code: "weak_password", message: "Password must be at least 6 characters." } };
    }
    const existing = Object.values(this.state.tenants).find((t) => t.email === cleanEmail);
    if (existing) {
      return { ok: false, error: { code: "email_taken", message: "An account with this email already exists." } };
    }

    const tenantId = `ten_${randomBytes(6).toString("hex")}`;
    const now = new Date().toISOString();
    const tenant = {
      id: tenantId,
      email: cleanEmail,
      org_name: String(org_name || cleanEmail.split("@")[0]).trim().slice(0, 80),
      password_hash: hashPassword(password),
      plan_id: "free_trial",
      billing_month: currentBillingMonth(),
      scans_used: 0,
      rl_builds_used: 0,
      stripe_customer_id: null,
      stripe_subscription_id: null,
      created_at: now,
    };
    this.state.tenants[tenantId] = tenant;

    // Issue starter API key for new tenant
    const keyToken = `rea_sk_live_${randomBytes(12).toString("hex")}`;
    this.state.api_keys[keyToken] = {
      id: `key_${randomBytes(4).toString("hex")}`,
      tenant_id: tenantId,
      name: "Starter API Key",
      prefix: `${keyToken.slice(0, 18)}…`,
      token: keyToken,
      calls: 0,
      revoked: false,
      created_at: now,
    };

    const sessionToken = `rea_sess_${randomBytes(16).toString("hex")}`;
    this.state.sessions[sessionToken] = {
      token: sessionToken,
      tenant_id: tenantId,
      created_at: now,
    };
    this.save();

    return {
      ok: true,
      session_token: sessionToken,
      tenant: this.sanitizeTenant(tenant),
      api_keys: this.listTenantKeys(tenantId),
    };
  }

  login({ email, password }) {
    const cleanEmail = String(email || "").trim().toLowerCase();
    const tenant = Object.values(this.state.tenants).find((t) => t.email === cleanEmail);
    if (!tenant || !verifyPassword(password, tenant.password_hash)) {
      return { ok: false, error: { code: "invalid_credentials", message: "Invalid email or password." } };
    }

    const sessionToken = `rea_sess_${randomBytes(16).toString("hex")}`;
    this.state.sessions[sessionToken] = {
      token: sessionToken,
      tenant_id: tenant.id,
      created_at: new Date().toISOString(),
    };
    this.save();

    return {
      ok: true,
      session_token: sessionToken,
      tenant: this.sanitizeTenant(tenant),
      api_keys: this.listTenantKeys(tenant.id),
    };
  }

  resolveTenantFromRequest(req) {
    const sessHeader = String(req.headers["x-studio-session"] || "").trim();
    if (sessHeader && this.state.sessions[sessHeader]) {
      const t = this.state.tenants[this.state.sessions[sessHeader].tenant_id];
      if (t) return t;
    }
    return this.state.tenants[this.state.default_tenant_id] || Object.values(this.state.tenants)[0];
  }

  authenticateApiKey(req) {
    const auth = String(req.headers.authorization || "");
    const token = auth.replace(/^Bearer\s+/i, "").trim();
    const keyRec = this.state.api_keys[token];
    if (!keyRec || keyRec.revoked) return null;
    const tenant = this.state.tenants[keyRec.tenant_id];
    if (!tenant) return null;
    keyRec.calls += 1;
    this.save();
    return { keyRec, tenant };
  }

  // -------------------------------------------------------------------------
  // API Key Management (Per-Tenant)
  // -------------------------------------------------------------------------
  listTenantKeys(tenantId) {
    return Object.values(this.state.api_keys)
      .filter((k) => k.tenant_id === tenantId && !k.revoked)
      .map((k) => ({ ...k }));
  }

  createApiKey(tenantId, label) {
    const tenant = this.state.tenants[tenantId];
    if (!tenant) return { ok: false, error: { message: "Tenant not found" } };
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

    const token = `rea_sk_live_${randomBytes(12).toString("hex")}`;
    const created = {
      id: `key_${randomBytes(4).toString("hex")}`,
      tenant_id: tenantId,
      name: String(label || "CI/CD Pipeline Key").slice(0, 64),
      prefix: `${token.slice(0, 18)}…`,
      token,
      calls: 0,
      revoked: false,
      created_at: new Date().toISOString(),
    };
    this.state.api_keys[token] = created;
    this.save();
    return { ok: true, key: created, api_keys: this.listTenantKeys(tenantId) };
  }

  revokeApiKey(tenantId, keyId) {
    const found = Object.values(this.state.api_keys).find(
      (k) => k.tenant_id === tenantId && k.id === keyId && !k.revoked,
    );
    if (!found) return { ok: false, error: { message: "Key not found" } };
    found.revoked = true;
    this.save();
    return { ok: true, api_keys: this.listTenantKeys(tenantId) };
  }

  // -------------------------------------------------------------------------
  // Quota Metering & Enforcement
  // -------------------------------------------------------------------------
  checkAndConsumeQuota(tenant, kind = "scan") {
    this.ensureCurrentBillingPeriod(tenant);
    const plan = PLANS[tenant.plan_id] || PLANS.free_trial;

    if (kind === "rl_build") {
      if (plan.rl_build_limit !== null && tenant.rl_builds_used >= plan.rl_build_limit) {
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
      tenant.rl_builds_used += 1;
      this.save();
      return { ok: true, tenant: this.sanitizeTenant(tenant) };
    }

    if (plan.scan_limit !== null && tenant.scans_used >= plan.scan_limit) {
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
    tenant.scans_used += 1;
    this.save();
    return { ok: true, tenant: this.sanitizeTenant(tenant) };
  }

  // -------------------------------------------------------------------------
  // Stripe Checkout + Signed Webhook Provisioning
  // -------------------------------------------------------------------------
  async createCheckoutSession(tenant, planId, originUrl) {
    const plan = PLANS[planId];
    if (!plan || plan.unit_amount_cents <= 0) {
      return { ok: false, error: { message: "Select a paid plan (indie, team, or ai_lab)." } };
    }

    // Production Mode: Real Stripe Checkout Session via official REST API
    if (this.stripeSecretKey) {
      const form = new URLSearchParams();
      form.set("mode", "subscription");
      form.set("customer_email", tenant.email);
      form.set("client_reference_id", tenant.id);
      form.set("success_url", `${originUrl}/?billing=success&plan=${encodeURIComponent(plan.id)}`);
      form.set("cancel_url", `${originUrl}/?billing=canceled`);
      form.set("metadata[tenant_id]", tenant.id);
      form.set("metadata[plan_id]", plan.id);
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

    // Sandbox Mode (when STRIPE_SECRET_KEY is not set yet): allows testing full checkout -> webhook -> unlock loop
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
      tenant: this.sanitizeTenant(tenant),
    };
  }

  applyPlanProvisioning(tenantId, planId, meta = {}) {
    const tenant = this.state.tenants[tenantId];
    const plan = PLANS[planId];
    if (!tenant || !plan) {
      return { ok: false, error: { message: "Unknown tenant or plan" } };
    }
    tenant.plan_id = plan.id;
    if (meta.stripe_customer_id) tenant.stripe_customer_id = meta.stripe_customer_id;
    if (meta.stripe_subscription_id) tenant.stripe_subscription_id = meta.stripe_subscription_id;

    const eventRecord = {
      id: `evt_${randomBytes(6).toString("hex")}`,
      tenant_id: tenant.id,
      email: tenant.email,
      plan_id: plan.id,
      amount_usd: plan.price_monthly_usd,
      source: meta.source || "stripe_webhook",
      created_at: new Date().toISOString(),
    };
    this.state.billing_events.unshift(eventRecord);
    this.state.billing_events = this.state.billing_events.slice(0, 100);
    this.save();

    return {
      ok: true,
      tenant: this.sanitizeTenant(tenant),
      event: eventRecord,
    };
  }

  verifyAndHandleStripeWebhook(rawBodyBuffer, signatureHeader) {
    if (!this.stripeWebhookSecret) {
      return { ok: false, status: 400, error: { message: "STRIPE_WEBHOOK_SECRET not configured" } };
    }
    const sigParts = Object.fromEntries(
      String(signatureHeader || "")
        .split(",")
        .map((kv) => kv.trim().split("="))
        .filter((p) => p.length === 2),
    );
    const timestamp = sigParts.t;
    const v1 = sigParts.v1;
    if (!timestamp || !v1) {
      return { ok: false, status: 400, error: { message: "Malformed Stripe-Signature header" } };
    }

    const ageSec = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
    if (!Number.isFinite(ageSec) || ageSec > 300) {
      return { ok: false, status: 400, error: { message: "Webhook timestamp outside 5-minute tolerance" } };
    }

    const signedPayload = `${timestamp}.${rawBodyBuffer.toString("utf8")}`;
    const expectedHex = createHmac("sha256", this.stripeWebhookSecret).update(signedPayload).digest("hex");
    const expectedBuf = Buffer.from(expectedHex, "utf8");
    const providedBuf = Buffer.from(v1, "utf8");
    if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
      return { ok: false, status: 400, error: { message: "Invalid Stripe webhook signature" } };
    }

    const event = JSON.parse(rawBodyBuffer.toString("utf8"));
    if (event.type === "checkout.session.completed") {
      const obj = event.data?.object || {};
      const tenantId = obj.metadata?.tenant_id || obj.client_reference_id;
      const planId = obj.metadata?.plan_id || "team";
      return this.applyPlanProvisioning(tenantId, planId, {
        source: "stripe_webhook",
        stripe_customer_id: obj.customer || null,
        stripe_subscription_id: obj.subscription || null,
      });
    }
    if (event.type === "customer.subscription.deleted") {
      const subId = event.data?.object?.id;
      const tenant = Object.values(this.state.tenants).find((t) => t.stripe_subscription_id === subId);
      if (tenant) {
        return this.applyPlanProvisioning(tenant.id, "free_trial", { source: "subscription_canceled" });
      }
    }
    return { ok: true, ignored: event.type };
  }
}
