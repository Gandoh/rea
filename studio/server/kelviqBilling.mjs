import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Load .env.local / .env automatically per Kelviq's "Set up with AI" Step 1 convention
 * without overwriting environment variables already injected by Railway/Render/Docker.
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
    kelviq_identifier: null,
    name: "Free Starter",
    price_monthly_usd: 0,
    price_yearly_usd: 0,
    daily_scans: 3,
    features: ["3 Contract & APK Rug Scans / day", "Top 10 Market Ticker", "Public Share Cards"],
  },
  indie: {
    id: "indie",
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
  team: {
    id: "team",
    kelviq_identifier: process.env.KELVIQ_WHALE_PLAN_ID || "alphashield-whale",
    name: "Whale Desk & API",
    price_monthly_usd: 49,
    price_yearly_usd: 399,
    daily_scans: null,
    features: [
      "Everything in Pro Trader + REST API Access (/api/v1/*)",
      "Multi-Chain Deep EVM Selector & Proxy Trap Audits",
      "CI/CD GitHub Action Release Gate + 20 API Keys",
      "Priority Merchant-of-Record Invoicing via Kelviq",
    ],
  },
  ai_lab: {
    id: "ai_lab",
    kelviq_identifier: process.env.KELVIQ_ENTERPRISE_PLAN_ID || "rea-ai-lab",
    name: "Enterprise & AI Lab",
    price_monthly_usd: 299,
    price_yearly_usd: 2499,
    daily_scans: null,
    features: [
      "Full REA Cloud Studio + HAR-to-RL AgentEnv Factory",
      "Unlimited Team Seats, Custom Verifiers & Dedicated Support",
    ],
  },
});

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

  get environment() {
    const raw = (process.env.KELVIQ_ENV || "sandbox").trim();
    return raw === "production" ? "production" : "sandbox";
  }

  get isConfigured() {
    return Boolean(this.serverKey);
  }

  async init() {
    if (this.sdkLoaded) return;
    this.sdkLoaded = true;
    try {
      const mod = await import("@kelviq/node-sdk");
      this.sdk = mod;
      if (this.serverKey) {
        const env = mod.environmentFromEnv(process.env.KELVIQ_ENV);
        this.client = new mod.Kelviq({
          accessToken: this.serverKey,
          environment: env,
          enableCache: true,
          cacheTtlMs: 60_000,
        });
      }
    } catch {
      this.sdk = null;
      this.client = null;
    }
  }

  statusSummary() {
    return {
      provider: "kelviq",
      organization: process.env.KELVIQ_ORG_NAME || "Gandoh Bah Ai",
      environment: this.environment,
      live_keys_configured: this.isConfigured,
      client_key_present: Boolean(this.clientKey),
      webhook_secret_present: Boolean(this.webhookSecret),
      sdk_installed: Boolean(this.sdk),
      plans: Object.values(ALPHASHIELD_PLANS),
    };
  }

  planIdentifierFor(planId) {
    if (planId === "indie" || planId === "pro" || planId === "alphashield-pro") {
      return { internalId: "indie", kelviqPlan: process.env.KELVIQ_PRO_PLAN_ID || "alphashield-pro" };
    }
    if (planId === "team" || planId === "whale" || planId === "alphashield-whale") {
      return { internalId: "team", kelviqPlan: process.env.KELVIQ_WHALE_PLAN_ID || "alphashield-whale" };
    }
    if (planId === "ai_lab" || planId === "rea-ai-lab") {
      return { internalId: "ai_lab", kelviqPlan: process.env.KELVIQ_ENTERPRISE_PLAN_ID || "rea-ai-lab" };
    }
    return { internalId: "indie", kelviqPlan: process.env.KELVIQ_PRO_PLAN_ID || "alphashield-pro" };
  }

  internalPlanFromKelviq(kelviqIdentifier) {
    const clean = String(kelviqIdentifier || "").toLowerCase();
    if (clean.includes("whale") || clean.includes("team")) return "team";
    if (clean.includes("lab") || clean.includes("enterprise")) return "ai_lab";
    return "indie";
  }

  async ensureCustomer(tenant) {
    await this.init();
    if (!this.client) return;
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
        // Ignore if customer already exists concurrently
      }
    }
  }

  async createCheckoutSession({ tenant, planId, chargePeriod = "MONTHLY", originUrl }) {
    await this.init();
    const { internalId, kelviqPlan } = this.planIdentifierFor(planId);
    const planMeta = ALPHASHIELD_PLANS[internalId] || ALPHASHIELD_PLANS.indie;
    const period = chargePeriod === "YEARLY" ? "YEARLY" : "MONTHLY";
    const successUrl = `${originUrl}/alphashield?checkout=success&plan=${encodeURIComponent(internalId)}`;

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

    // Local/Preview Sandbox fallback until KELVIQ_SERVER_API_KEY is added to .env.local or Railway/Render
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
    if (!this.client) {
      return {
        ok: false,
        error: {
          message:
            "Add KELVIQ_SERVER_API_KEY to .env.local or hosting secrets to open the live Kelviq customer billing portal.",
        },
      };
    }
    await this.ensureCustomer(tenant);
    const portal = await this.client.portal.createSession({ customerId: tenant.id });
    return { ok: true, portal };
  }

  async activateLicenseKey({ licenseKey, tenant, instanceName = "web-browser" }) {
    await this.init();
    const cleanKey = String(licenseKey || "").trim();
    if (!cleanKey) {
      return { ok: false, error: { message: "Enter a valid license key." } };
    }

    if (this.client) {
      const validation = await this.client.license.validate({ licenseKey: cleanKey });
      if (!validation.valid) {
        return {
          ok: false,
          error: { message: validation.detail || "License key is invalid or expired." },
        };
      }
      const activated = await this.client.license.activate({
        licenseKey: cleanKey,
        customerId: tenant.id,
        instanceName,
      });
      const mappedPlan = this.internalPlanFromKelviq(activated.license?.plan?.identifier);
      return {
        ok: true,
        mode: `kelviq_${this.environment}`,
        plan_id: mappedPlan,
        instance_id: activated.instanceId,
        expires_on: activated.expiresOn || null,
      };
    }

    // Preview/Demo license key support before live keys are pasted into hosting env
    if (/^(ALPHASHIELD|KVQ|PRO)-/i.test(cleanKey) && cleanKey.length >= 10) {
      const mappedPlan = /WHALE|TEAM/i.test(cleanKey) ? "team" : "indie";
      return {
        ok: true,
        mode: "kelviq_preview_sandbox",
        plan_id: mappedPlan,
        instance_id: `inst_${randomBytes(6).toString("hex")}`,
        expires_on: null,
      };
    }
    return {
      ok: false,
      error: {
        message:
          "Unrecognized license key. In preview mode, try ALPHASHIELD-PRO-2026 (in production, keys validate against api.kelviq.com).",
      },
    };
  }

  async reportScanUsage(customerId, featureId = "contract-scans") {
    await this.init();
    if (!this.client) return;
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
    if (this.sdk?.validateEvent) {
      return this.sdk.validateEvent(rawBodyBuffer, headers, this.webhookSecret);
    }

    // Exact Kelviq v1 HMAC-SHA256 verification fallback
    const lower = {};
    for (const [k, v] of Object.entries(headers || {})) {
      lower[k.toLowerCase()] = Array.isArray(v) ? v[0] : v;
    }
    const id = lower["webhook-id"];
    const ts = lower["webhook-timestamp"];
    const sig = lower["webhook-signature"];
    if (!id || !ts || !sig || !String(sig).startsWith("v1,")) {
      throw new Error("Missing or malformed Kelviq webhook signature headers.");
    }
    const body = rawBodyBuffer.toString("utf8");
    const computed = createHmac("sha256", this.webhookSecret)
      .update(`${id}.${ts}.${body}`, "utf8")
      .digest("hex");
    const a = Buffer.from(computed, "hex");
    const b = Buffer.from(String(sig).slice(3), "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new Error("Kelviq webhook signature mismatch.");
    }
    return JSON.parse(body);
  }
}
