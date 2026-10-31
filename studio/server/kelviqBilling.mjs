import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Load .env.local / .env without overwriting environment variables already injected by host/container.
 */
export function loadDotEnvFiles(dirs = []) {
  for (const dir of dirs) {
    for (const file of [".env.local", ".env"]) {
      const full = join(dir, file);
      if (!existsSync(full)) continue;
      const lines = readFileSync(full, "utf8").split(/\r?\n/u);
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq <= 0) continue;
        const key = line.slice(0, eq).trim();
        let val = line.slice(eq + 1).trim();
        if (
          (val.startsWith('"') && val.endsWith('"')) ||
          (val.startsWith("'") && val.endsWith("'"))
        ) {
          val = val.slice(1, -1);
        }
        if (process.env[key] === undefined) {
          process.env[key] = val;
        }
      }
    }
  }
}

export const ALPHASHIELD_PLANS = Object.freeze({
  free_trial: {
    id: "free_trial",
    product: "alphashield",
    kelviq_identifier: null,
    name: "Free Starter",
    price_monthly_usd: 0,
    price_yearly_usd: 0,
    daily_scans: 3,
    features: ["3 Contract & APK Rug Scans / day", "Top 10 Market Ticker", "Public Share Cards"],
  },
  alphashield_pro: {
    id: "alphashield_pro",
    product: "alphashield",
    kelviq_identifier: process.env.KELVIQ_PRO_PLAN_ID || "alphashield-pro",
    name: "AlphaShield Pro Trader",
    price_monthly_usd: 19,
    price_yearly_usd: 159,
    daily_scans: null,
    features: [
      "Unlimited Live Smart Contract Rug & Honeypot Scans",
      "Unlimited APK & Extension Malware/Drainer Checks",
      "Custom Breakout Watchlist & Whale Momentum Signals",
      "Instant Pro License Key Activation across Phone & Desktop",
    ],
  },
  alphashield_whale: {
    id: "alphashield_whale",
    product: "alphashield",
    kelviq_identifier: process.env.KELVIQ_WHALE_PLAN_ID || "alphashield-whale",
    name: "Whale Desk & Alerts",
    price_monthly_usd: 49,
    price_yearly_usd: 399,
    daily_scans: null,
    features: [
      "Everything in Pro Trader + Priority Deep EVM Audits",
      "Multi-Chain Deep EVM Selector & Proxy Trap Audits",
      "Priority Merchant-of-Record Invoicing via Kelviq",
    ],
  },
});

const MONTHLY_DURATION_MS = 31 * 24 * 60 * 60 * 1000;

export class KelviqBillingBridge {
  constructor() {
    this.sdk = null;
    this.client = null;
    this.sdkLoaded = false;
  }

  get serverKey() {
    return (process.env.KELVIQ_SERVER_API_KEY || process.env.KELVIQ_API_KEY || "").trim();
  }

  get clientKey() {
    return (process.env.KELVIQ_CLIENT_API_KEY || "").trim();
  }

  get webhookSecret() {
    return (process.env.KELVIQ_WEBHOOK_SECRET || "").trim();
  }

  get merchantWallet() {
    const w = (process.env.ALPHASHIELD_MERCHANT_WALLET || "").trim();
    return /^0x[0-9a-fA-F]{40}$/.test(w) ? w : null;
  }

  /**
   * Direct USDT activation requires BOTH a valid merchant wallet AND explicit opt-in
   * (`ALPHASHIELD_ENABLE_DIRECT_USDT=true`) using tenant-bound payment intents.
   */
  get isDirectUsdtEnabled() {
    return process.env.ALPHASHIELD_ENABLE_DIRECT_USDT === "true" && Boolean(this.merchantWallet);
  }

  get environment() {
    const raw = (process.env.KELVIQ_ENV || "sandbox").trim();
    return raw === "production" ? "production" : "sandbox";
  }

  get isConfigured() {
    return Boolean(this.serverKey);
  }

  isSandboxAllowed({ stripeConfigured = false } = {}) {
    return (
      process.env.ALLOW_SANDBOX_BILLING === "true" &&
      process.env.NODE_ENV !== "production" &&
      !this.isConfigured &&
      !stripeConfigured
    );
  }

  async init() {
    if (this.sdkLoaded) return;
    this.sdkLoaded = true;
    try {
      const mod = await import("@kelviq/node-sdk");
      this.sdk = mod;
      if (this.serverKey) {
        const env = mod.environmentFromEnv(process.env.KELVIQ_ENV);
        const customBaseUrl = (process.env.KELVIQ_API_BASE_URL || "").trim();
        this.client = new mod.Kelviq({
          accessToken: this.serverKey,
          environment: env,
          ...(customBaseUrl ? { baseUrl: customBaseUrl, edgeApiUrl: customBaseUrl } : {}),
          logger: false, // Prevent @kelviq/node-sdk from logging plaintext license keys to stdout
          enableCache: true,
          cacheTtlMs: 60_000,
        });
      }
    } catch {
      this.sdk = null;
      this.client = null;
    }
  }

  /**
   * Public status summary — NEVER exposes `merchant_wallet` to unauthenticated or general status polls.
   */
  statusSummary({ stripeConfigured = false } = {}) {
    return {
      provider: "kelviq",
      organization: process.env.KELVIQ_ORG_NAME || "Gandoh Bah Ai",
      environment: this.environment,
      live_keys_configured: this.isConfigured,
      client_key_present: Boolean(this.clientKey),
      webhook_secret_present: Boolean(this.webhookSecret),
      sandbox_enabled: this.isSandboxAllowed({ stripeConfigured }),
      direct_usdt_enabled: this.isDirectUsdtEnabled,
      sdk_installed: Boolean(this.sdk),
      plans: Object.values(ALPHASHIELD_PLANS),
    };
  }

  planIdentifierFor(planId) {
    const clean = String(planId || "").trim().toLowerCase();
    if (clean === "alphashield_whale" || clean === "whale" || clean === "alphashield-whale") {
      return {
        product: "alphashield",
        internalId: "alphashield_whale",
        kelviqPlan: process.env.KELVIQ_WHALE_PLAN_ID || "alphashield-whale",
      };
    }
    if (clean === "alphashield_pro" || clean === "alphashield-pro") {
      return {
        product: "alphashield",
        internalId: "alphashield_pro",
        kelviqPlan: process.env.KELVIQ_PRO_PLAN_ID || "alphashield-pro",
      };
    }
    return null;
  }

  /**
   * Strictly resolves an explicit Kelviq plan identifier to `{ product, plan_id }`.
   * Returns `null` when missing or unrecognized — NEVER defaults to AlphaShield or Studio.
   */
  resolveEntitlementFromKelviq(kelviqIdentifier) {
    const clean = String(kelviqIdentifier || "").trim().toLowerCase();
    if (!clean) return null;

    const enterpriseId = String(process.env.KELVIQ_ENTERPRISE_PLAN_ID || "rea-ai-lab")
      .trim()
      .toLowerCase();
    const studioTeamId = String(process.env.KELVIQ_STUDIO_TEAM_PLAN_ID || "rea-shipgate-team")
      .trim()
      .toLowerCase();
    const studioIndieId = String(process.env.KELVIQ_STUDIO_INDIE_PLAN_ID || "rea-indie")
      .trim()
      .toLowerCase();

    if (clean === enterpriseId || clean === "ai_lab") {
      return { product: "studio", plan_id: "ai_lab" };
    }
    if (clean === studioTeamId) {
      return { product: "studio", plan_id: "team" };
    }
    if (clean === studioIndieId) {
      return { product: "studio", plan_id: "indie" };
    }

    const whaleId = String(process.env.KELVIQ_WHALE_PLAN_ID || "alphashield-whale")
      .trim()
      .toLowerCase();
    const proId = String(process.env.KELVIQ_PRO_PLAN_ID || "alphashield-pro")
      .trim()
      .toLowerCase();

    if (clean === whaleId || clean === "alphashield_whale") {
      return { product: "alphashield", plan_id: "alphashield_whale" };
    }
    if (clean === proId || clean === "alphashield_pro") {
      return { product: "alphashield", plan_id: "alphashield_pro" };
    }

    return null;
  }

  async ensureCustomer(tenant) {
    await this.init();
    if (!this.client || !tenant) return;
    try {
      await this.client.customers.retrieve({ customerId: tenant.id });
    } catch {
      try {
        await this.client.customers.create({
          customerId: tenant.id,
          email: tenant.email,
          name: tenant.org_name,
          metadata: { source: "alphashield" },
        });
      } catch {
        // Ignore concurrent creation race
      }
    }
  }

  async createCheckoutSession({
    tenant,
    planId,
    chargePeriod = "MONTHLY",
    originUrl,
    stripeConfigured = false,
  }) {
    await this.init();
    if (!tenant) {
      return { ok: false, status: 401, error: { message: "Sign in to start a subscription checkout." } };
    }
    const resolved = this.planIdentifierFor(planId);
    if (!resolved) {
      return {
        ok: false,
        status: 400,
        error: { message: "Select a valid AlphaShield plan (alphashield_pro or alphashield_whale)." },
      };
    }
    const { product, internalId, kelviqPlan } = resolved;
    const planMeta = ALPHASHIELD_PLANS[internalId];
    const period = chargePeriod === "YEARLY" ? "YEARLY" : "MONTHLY";
    const successUrl = `${originUrl}/alphashield?billing_return=1&plan=${encodeURIComponent(internalId)}`;

    if (this.client) {
      await this.ensureCustomer(tenant);
      const session = await this.client.checkout.createSession({
        planIdentifier: kelviqPlan,
        chargePeriod: period,
        customerId: tenant.id,
        successUrl,
        ...(process.env.KELVIQ_PRICING_TABLE_ID
          ? { pricingTableId: process.env.KELVIQ_PRICING_TABLE_ID }
          : {}),
        metadata: {
          tenant_id: tenant.id,
          product,
          plan_id: internalId,
          kelviq_plan: kelviqPlan,
        },
      });
      return {
        ok: true,
        provider: "kelviq",
        mode: `kelviq_${this.environment}`,
        checkout_session_id: session.checkoutSessionId,
        checkout_url: session.checkoutUrl,
        plan: planMeta,
      };
    }

    if (!this.isSandboxAllowed({ stripeConfigured })) {
      return {
        ok: false,
        status: 503,
        error: {
          code: "billing_not_configured",
          message:
            "Live Kelviq billing is not configured on this server (sandbox billing is disabled unless ALLOW_SANDBOX_BILLING=true in non-production).",
        },
      };
    }

    return {
      ok: true,
      provider: "kelviq",
      mode: "kelviq_preview_sandbox",
      checkout_session_id: `kvq_cs_${randomBytes(8).toString("hex")}`,
      plan: {
        ...planMeta,
        kelviq_identifier: kelviqPlan,
        charge_period: period,
      },
    };
  }

  async createPortalSession({ tenant }) {
    await this.init();
    if (!tenant) {
      return { ok: false, status: 401, error: { message: "Sign in to access your billing portal." } };
    }
    if (!this.client) {
      return {
        ok: false,
        status: 503,
        error: { message: "Live Kelviq billing is not configured on this server." },
      };
    }
    await this.ensureCustomer(tenant);
    const portal = await this.client.portal.createSession({ customerId: tenant.id });
    return { ok: true, portal };
  }

  async activateLicenseKey({
    licenseKey,
    tenant,
    instanceName = "web-browser",
    stripeConfigured = false,
  }) {
    await this.init();
    if (!tenant) {
      return { ok: false, status: 401, error: { message: "Sign in before activating a license key." } };
    }
    const cleanKey = String(licenseKey || "").trim();
    if (!cleanKey || cleanKey.length > 256) {
      return { ok: false, status: 400, error: { message: "Enter a valid license key." } };
    }
    const safeInstanceName = String(instanceName || "web-browser").trim().slice(0, 64) || "web-browser";

    if (this.client) {
      const validation = await this.client.license.validate({ licenseKey: cleanKey });
      if (!validation?.valid) {
        return {
          ok: false,
          status: 400,
          error: { code: "invalid_license", message: validation?.detail || "License key is invalid or expired." },
        };
      }

      // Enforce customer ownership binding before activating
      const licObj = validation.license || {};
      const boundCustomerId = String(licObj.customerId || licObj.customer?.id || "").trim();
      const boundEmail = String(licObj.customerEmail || licObj.customer?.email || "")
        .trim()
        .toLowerCase();

      if (boundCustomerId && boundCustomerId !== tenant.id) {
        return {
          ok: false,
          status: 403,
          error: {
            code: "license_customer_mismatch",
            message: "This license key belongs to a different customer account.",
          },
        };
      }
      if (boundEmail && boundEmail !== String(tenant.email || "").toLowerCase()) {
        return {
          ok: false,
          status: 403,
          error: {
            code: "license_customer_mismatch",
            message: "This license key email does not match your signed-in workspace.",
          },
        };
      }

      const preExpires = licObj.expiresOn || licObj.expiresAt || validation.expiresOn || null;
      if (preExpires && Date.parse(preExpires) <= Date.now()) {
        return {
          ok: false,
          status: 400,
          error: { code: "license_expired", message: "License key has expired." },
        };
      }

      const activated = await this.client.license.activate({
        licenseKey: cleanKey,
        customerId: tenant.id,
        instanceName: safeInstanceName,
      });

      const actLic = activated?.license || licObj;
      const actCustId = String(actLic?.customerId || actLic?.customer?.id || "").trim();
      if (actCustId && actCustId !== tenant.id) {
        return {
          ok: false,
          status: 403,
          error: {
            code: "license_customer_mismatch",
            message: "Activated license customer does not match signed-in workspace.",
          },
        };
      }

      const planIdent = actLic?.plan?.identifier || actLic?.planIdentifier || licObj?.plan?.identifier;
      const entitlement = this.resolveEntitlementFromKelviq(planIdent);
      if (!entitlement) {
        return {
          ok: false,
          status: 400,
          error: {
            code: "unknown_license_plan",
            message: "License key does not map to a recognized product plan.",
          },
        };
      }

      const expiresOn =
        activated?.expiresOn ||
        actLic?.expiresOn ||
        actLic?.expiresAt ||
        preExpires ||
        new Date(Date.now() + MONTHLY_DURATION_MS).toISOString();

      if (Date.parse(expiresOn) <= Date.now()) {
        return {
          ok: false,
          status: 400,
          error: { code: "license_expired", message: "License key has expired." },
        };
      }

      return {
        ok: true,
        mode: `kelviq_${this.environment}`,
        product: entitlement.product,
        plan_id: entitlement.plan_id,
        instance_id: activated.instanceId || null,
        expires_on: expiresOn,
      };
    }

    if (!this.isSandboxAllowed({ stripeConfigured })) {
      return {
        ok: false,
        status: 503,
        error: {
          code: "license_server_unconfigured",
          message:
            "License verification service is not configured on this server (demo license keys are disabled unless ALLOW_SANDBOX_BILLING=true in non-production).",
        },
      };
    }

    if (/^(ALPHASHIELD|KVQ)-/i.test(cleanKey) && cleanKey.length >= 12) {
      const mappedPlan = /WHALE/i.test(cleanKey) ? "alphashield_whale" : "alphashield_pro";
      return {
        ok: true,
        mode: "kelviq_preview_sandbox",
        product: "alphashield",
        plan_id: mappedPlan,
        instance_id: `inst_${randomBytes(6).toString("hex")}`,
        expires_on: new Date(Date.now() + MONTHLY_DURATION_MS).toISOString(),
      };
    }
    return {
      ok: false,
      status: 400,
      error: { message: "Invalid sandbox license key." },
    };
  }

  async reportScanUsage(customerId, featureId = "contract-scans") {
    await this.init();
    if (!this.client || !customerId) return;
    try {
      await this.client.reporting.reportUsage({
        customerId,
        featureId,
        value: 1,
        behaviour: "DELTA",
      });
    } catch {
      // SDK queues offline reports automatically
    }
  }

  verifyAndParseWebhook(rawBodyBuffer, headers) {
    if (!this.webhookSecret) {
      throw new Error("KELVIQ_WEBHOOK_SECRET is not configured.");
    }

    const lower = {};
    for (const [k, v] of Object.entries(headers || {})) {
      lower[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
    }
    const id = String(lower["webhook-id"] || "").trim();
    const ts = String(lower["webhook-timestamp"] || "").trim();
    const sigHeader = String(lower["webhook-signature"] || "").trim();
    if (!id || !ts || !sigHeader) {
      throw new Error("Missing Kelviq webhook signature headers.");
    }

    const tsNum = Number(ts);
    const ageSec = Math.abs(Math.floor(Date.now() / 1000) - tsNum);
    if (!Number.isFinite(ageSec) || ageSec > 300) {
      throw new Error("Kelviq webhook timestamp outside 5-minute tolerance.");
    }

    if (this.sdk?.validateEvent && /^v1,[0-9a-fA-F]{64}$/.test(sigHeader)) {
      const event = this.sdk.validateEvent(rawBodyBuffer, headers, this.webhookSecret);
      return { event, webhookId: id };
    }

    const body = rawBodyBuffer.toString("utf8");
    const utf8Digest = createHmac("sha256", Buffer.from(this.webhookSecret, "utf8"))
      .update(`${id}.${ts}.${body}`, "utf8")
      .digest();
    const expectedBuffers = [
      Buffer.from(utf8Digest.toString("hex"), "utf8"),
      Buffer.from(utf8Digest.toString("base64"), "utf8"),
    ];
    if (this.webhookSecret.startsWith("whsec_")) {
      const decodedSecret = Buffer.from(this.webhookSecret.slice("whsec_".length), "base64");
      const b64KeyDigest = createHmac("sha256", decodedSecret)
        .update(`${id}.${ts}.${body}`, "utf8")
        .digest();
      expectedBuffers.push(
        Buffer.from(b64KeyDigest.toString("base64"), "utf8"),
        Buffer.from(b64KeyDigest.toString("hex"), "utf8"),
      );
    }

    const candidates = sigHeader
      .split(/\s+/)
      .map((s) => s.trim())
      .filter((s) => s.startsWith("v1,"))
      .map((s) => s.slice(3));

    if (candidates.length === 0) {
      throw new Error("Malformed Kelviq webhook-signature header.");
    }

    const matched = candidates.some((cand) => {
      const candBuf = Buffer.from(cand, "utf8");
      return expectedBuffers.some(
        (expBuf) => candBuf.length === expBuf.length && timingSafeEqual(candBuf, expBuf),
      );
    });

    if (!matched) {
      throw new Error("Kelviq webhook signature mismatch.");
    }

    return { event: JSON.parse(body), webhookId: id };
  }
}
