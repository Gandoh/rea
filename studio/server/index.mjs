import { randomBytes, randomUUID, createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createInflateRaw } from "node:zlib";

import { ALPHASHIELD_PLANS, KelviqBillingBridge, loadDotEnvFiles } from "./kelviqBilling.mjs";
import { ReaStudioEngine } from "./reaEngine.mjs";
import { renderAuditMarkdown } from "./riskScoring.mjs";
import { ensureStudioSamples } from "./sampleFactory.mjs";
import {
  PLANS,
  TenantBillingStore,
  buildClearSessionCookie,
  buildSessionSetCookie,
} from "./tenantBilling.mjs";
import { crc32, zipDirectory } from "./zipBuilder.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const STUDIO_ROOT = resolve(__dirname, "..");
const PUBLIC_DIR = join(STUDIO_ROOT, "public");
const ALPHASHIELD_DIR = join(STUDIO_ROOT, "alphashield");
const REPO_ROOT = resolve(STUDIO_ROOT, "..");

loadDotEnvFiles([STUDIO_ROOT, REPO_ROOT]);

const RUNTIME_DIR = process.env.REA_STUDIO_RUNTIME_DIR || "/tmp/rea-studio-runtime";
const DATA_DIR =
  process.env.REA_STUDIO_DATA_DIR || process.env.STUDIO_DATA_DIR || join(RUNTIME_DIR, "data");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);

const MAX_UPLOAD_BYTES = 32 * 1024 * 1024; // 32 MiB per request
const MAX_TENANT_UPLOAD_BYTES = Number(
  process.env.REA_MAX_TENANT_UPLOAD_BYTES || 128 * 1024 * 1024,
); // 128 MiB retained per tenant
const UPLOAD_TTL_MS = Number(process.env.REA_UPLOAD_TTL_MS || 60 * 60 * 1000); // 1 hour

const MAX_ZIP_ENTRIES = 1000;
const MAX_ZIP_SINGLE_BYTES = 32 * 1024 * 1024; // 32 MiB
const MAX_ZIP_TOTAL_BYTES = 64 * 1024 * 1024; // 64 MiB
const MAX_ZIP_RATIO = 100; // max 100:1 expansion ratio (per-entry > 4 KiB & archive-wide > 16 KiB)

const ALLOWED_HEADERS =
  "content-type, authorization, x-filename, x-csrf-token, x-studio-session, stripe-signature, webhook-id, webhook-timestamp, webhook-signature";

const CORS_ALLOWLIST = new Set(
  String(process.env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
);

const OFFICIAL_STABLECOINS = Object.freeze({
  bsc: {
    chainIdHex: "0x38",
    minConfirmations: Math.max(15, Number(process.env.ALPHASHIELD_MIN_CONFIRMATIONS_BSC || 15)),
    tokens: [{ symbol: "USDT", address: "0x55d398326f99059ff775485246999027b3197955", decimals: 18 }],
    defaultRpcs: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org"],
  },
  ethereum: {
    chainIdHex: "0x1",
    minConfirmations: Math.max(12, Number(process.env.ALPHASHIELD_MIN_CONFIRMATIONS_ETHEREUM || 12)),
    tokens: [{ symbol: "USDT", address: "0xdac17f958d2ee523a2206206994597c13d831ec7", decimals: 6 }],
    defaultRpcs: ["https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com"],
  },
});

const MIME_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
});

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

export function assertProductionDataDirSafe(dataDir, env = process.env) {
  if (String(env?.NODE_ENV || "").toLowerCase() !== "production") {
    return;
  }
  const resolved = resolveRealOrLexicalPath(dataDir);
  const sysTmp = resolveRealOrLexicalPath(tmpdir());
  const ephemeralRoots = Array.from(
    new Set(["/tmp", "/var/tmp", "/private/tmp", sysTmp].map((p) => p.replace(/\/+$/u, ""))),
  );
  const isEphemeral = ephemeralRoots.some(
    (root) => root.length > 0 && (resolved === root || resolved.startsWith(`${root}/`)),
  );
  if (isEphemeral) {
    throw new Error(
      `Fatal configuration error: REA_STUDIO_DATA_DIR (${resolved}) resolves to ephemeral /tmp storage in NODE_ENV=production. ` +
        `Mount a persistent volume (e.g. /data) and set REA_STUDIO_DATA_DIR to durable storage before starting in production.`,
    );
  }
}

function ensurePrivateDir(dirPath) {
  mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dirPath, 0o700);
  } catch {
    // Best-effort on filesystems without POSIX mode bits.
  }
}

assertProductionDataDirSafe(DATA_DIR);
ensurePrivateDir(RUNTIME_DIR);
ensurePrivateDir(DATA_DIR);
export const samples = ensureStudioSamples(REPO_ROOT, RUNTIME_DIR);
export const engine = new ReaStudioEngine(REPO_ROOT, RUNTIME_DIR);
export const billing = new TenantBillingStore(join(DATA_DIR, "tenant-store.json"), {
  sqlitePath: join(DATA_DIR, "studio.sqlite"),
  bootstrapApiKey: process.env.REA_BOOTSTRAP_API_KEY,
});
export const kelviq = new KelviqBillingBridge();

class PayloadTooLargeError extends Error {
  constructor(maxBytes) {
    super(`Payload exceeds ${maxBytes} byte limit`);
    this.statusCode = 413;
  }
}

class BadRequestError extends Error {
  constructor(message, statusCode = 400, code = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Strictly Bounded O(1) LRU Rate Limiter
// ---------------------------------------------------------------------------
export class BoundedRateLimiter {
  constructor(limit, windowMs, maxBuckets = 4096) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxBuckets = Math.max(16, Number(maxBuckets) || 4096);
    /** @type {Map<string, { count: number, resetAt: number }>} */
    this.buckets = new Map();
  }

  check(key, now = Date.now()) {
    // Opportunistically reap expired oldest entries from Map head in O(1) amortized time
    for (const [k, b] of this.buckets) {
      if (b.resetAt <= now) {
        this.buckets.delete(k);
      } else {
        break;
      }
    }

    let entry = this.buckets.get(key);
    if (!entry || entry.resetAt <= now) {
      if (entry) this.buckets.delete(key);
      while (this.buckets.size >= this.maxBuckets) {
        const oldestKey = this.buckets.keys().next().value;
        if (oldestKey === undefined) break;
        this.buckets.delete(oldestKey);
      }
      entry = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, entry);
    } else {
      // Refresh LRU position
      this.buckets.delete(key);
      this.buckets.set(key, entry);
    }

    entry.count += 1;
    if (entry.count > this.limit) {
      const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      return { ok: false, retryAfterSec };
    }
    return { ok: true, retryAfterSec: 0 };
  }
}

const authPairLimiter = new BoundedRateLimiter(
  Number(process.env.REA_AUTH_RATE_LIMIT_PER_MIN || 12),
  60_000,
  Number(process.env.REA_RATE_LIMIT_MAX_BUCKETS || 4096),
);
const authAccountLimiter = new BoundedRateLimiter(
  Number(process.env.REA_AUTH_ACCOUNT_RATE_LIMIT_PER_MIN || 20),
  60_000,
  Number(process.env.REA_RATE_LIMIT_MAX_BUCKETS || 4096),
);
const authGlobalBreaker = new BoundedRateLimiter(
  Number(process.env.REA_AUTH_GLOBAL_BREAKER_PER_MIN || 300),
  60_000,
  64,
);
const apiLimiter = new BoundedRateLimiter(
  Number(process.env.REA_API_RATE_LIMIT_PER_MIN || 60),
  60_000,
  Number(process.env.REA_RATE_LIMIT_MAX_BUCKETS || 8192),
);

function normalizeIp(rawIp) {
  const clean = String(rawIp || "").trim();
  if (!clean) return "unknown";
  if (clean.startsWith("::ffff:")) {
    const v4 = clean.slice("::ffff:".length);
    if (isIP(v4) === 4) return v4;
  }
  return isIP(clean) ? clean : "unknown";
}

function getTrustedProxySet() {
  const raw = String(process.env.TRUSTED_PROXY_IPS || "").trim();
  if (!raw) return new Set();
  return new Set(
    raw
      .split(",")
      .map((ip) => normalizeIp(ip))
      .filter((ip) => ip !== "unknown"),
  );
}

/**
 * Resolves client IP using an explicit trusted-proxy list and right-to-left hop count.
 * Never trusts client-controlled X-Forwarded-For unless the direct peer socket IP is in TRUSTED_PROXY_IPS.
 */
export function getClientIp(req) {
  const socketIp = normalizeIp(req?.socket?.remoteAddress);
  const trustedProxies = getTrustedProxySet();
  if (trustedProxies.size === 0 || !trustedProxies.has(socketIp)) {
    return socketIp;
  }

  const xffRaw = String(req?.headers?.["x-forwarded-for"] || "").trim();
  if (!xffRaw) return socketIp;

  const chain = xffRaw
    .split(",")
    .map((part) => normalizeIp(part))
    .filter((ip) => ip !== "unknown");
  if (chain.length === 0) return socketIp;

  const maxHops = Math.max(1, Math.min(16, Number(process.env.TRUSTED_PROXY_HOPS || 1)));
  // Walk right-to-left through up to maxHops trusted proxies; stop at the first non-proxy client IP
  let candidate = chain[chain.length - 1];
  let hopsRemaining = maxHops;
  for (let i = chain.length - 1; i >= 0; i -= 1) {
    candidate = chain[i];
    if (!trustedProxies.has(candidate)) {
      return candidate;
    }
    hopsRemaining -= 1;
    if (hopsRemaining <= 0 && i > 0) {
      return chain[i - 1];
    }
  }
  return candidate;
}

function buildSecurityHeaders(req, extraHeaders = {}) {
  const isApi = String(req?.url || "").startsWith("/api/");
  const headers = {
    "x-content-type-options": "nosniff",
    ...(isApi ? { "x-frame-options": "DENY" } : {}),
    "content-security-policy": isApi
      ? "default-src 'none'; frame-ancestors 'none'"
      : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    ...(process.env.NODE_ENV === "production"
      ? { "strict-transport-security": "max-age=31536000; includeSubDomains" }
      : {}),
    ...extraHeaders,
  };

  const reqOrigin = String(req?.headers?.origin || "").trim();
  if (reqOrigin && CORS_ALLOWLIST.has(reqOrigin)) {
    headers["access-control-allow-origin"] = reqOrigin;
    headers["access-control-allow-headers"] = ALLOWED_HEADERS;
    headers["access-control-allow-methods"] = "GET, POST, OPTIONS";
    headers["access-control-allow-credentials"] = "true";
    headers.vary = "Origin";
  }
  return headers;
}

function sendJson(req, res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(
    status,
    buildSecurityHeaders(req, {
      "content-type": "application/json; charset=utf-8",
      "content-length": Buffer.byteLength(body),
      "cache-control": "no-store",
      ...extraHeaders,
    }),
  );
  res.end(body);
}

function enforceRateLimit(limiter, bucketKey, req, res) {
  const verdict = limiter.check(bucketKey);
  if (!verdict.ok) {
    sendJson(
      req,
      res,
      429,
      {
        ok: false,
        error: {
          code: "rate_limited",
          message: `Too many requests. Retry after ${verdict.retryAfterSec} second(s).`,
        },
      },
      { "retry-after": String(verdict.retryAfterSec) },
    );
    return false;
  }
  return true;
}

function readBodyBuffer(req, maxBytes = MAX_UPLOAD_BYTES) {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    req.on("data", (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        rejectPromise(new PayloadTooLargeError(maxBytes));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!settled) {
        settled = true;
        resolvePromise(Buffer.concat(chunks));
      }
    });
    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        rejectPromise(err);
      }
    });
  });
}

async function readJsonBody(req, maxBytes = 2 * 1024 * 1024) {
  const buf = await readBodyBuffer(req, maxBytes);
  if (buf.length === 0) return {};
  try {
    const parsed = JSON.parse(buf.toString("utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    throw new BadRequestError("Malformed JSON request body.", 400);
  }
}

function sanitizeFilename(name) {
  const clean = basename(String(name || "artifact.bin"))
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^\.+/, "");
  return (clean || "artifact.bin").slice(0, 128);
}

// ---------------------------------------------------------------------------
// Safe Public Origin Resolution (Fails Closed in Prod; Blocks Host Injection)
// ---------------------------------------------------------------------------
export function resolvePublicOrigin(req) {
  const configured = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configured) {
    let parsed;
    try {
      parsed = new URL(configured);
    } catch {
      throw new BadRequestError("Configured PUBLIC_BASE_URL is not a valid URL.", 503);
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new BadRequestError("PUBLIC_BASE_URL must use https: or http: protocol.", 503);
    }
    if (
      process.env.NODE_ENV === "production" &&
      parsed.protocol !== "https:" &&
      parsed.hostname !== "localhost" &&
      parsed.hostname !== "127.0.0.1"
    ) {
      throw new BadRequestError("PUBLIC_BASE_URL must use https: in production.", 503);
    }
    return parsed.origin;
  }

  if (process.env.NODE_ENV === "production") {
    throw new BadRequestError(
      "PUBLIC_BASE_URL must be configured in production before initiating billing redirects.",
      503,
      "missing_public_base_url",
    );
  }

  // Non-production fallback: NEVER read X-Forwarded-Host; allow only loopback or explicit dev preview hosts
  const rawHost = String(req?.headers?.host || "").trim();
  if (!rawHost) {
    return `http://127.0.0.1:${PORT}`;
  }
  let candidateUrl;
  try {
    candidateUrl = new URL(`http://${rawHost}`);
  } catch {
    throw new BadRequestError("Untrusted or malformed Host header rejected.", 400, "untrusted_host_header");
  }
  const hostname = candidateUrl.hostname.toLowerCase();
  const isLoopback =
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  const isE2bPreview = /^[0-9]+-[a-z0-9-]+\.e2b\.app$/.test(hostname);
  const devAllowlist = new Set(
    String(process.env.ALLOWED_DEV_HOSTS || "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
  if (!isLoopback && !isE2bPreview && !devAllowlist.has(hostname)) {
    throw new BadRequestError(
      "Untrusted Host header rejected for billing redirect. Configure PUBLIC_BASE_URL.",
      400,
      "untrusted_host_header",
    );
  }
  const proto = isE2bPreview ? "https" : "http";
  return `${proto}://${candidateUrl.host}`;
}

export function isRequestOriginAllowed(req, { requireBrowserOrigin = false } = {}) {
  const isProd = process.env.NODE_ENV === "production";
  const secFetchSite = String(req?.headers?.["sec-fetch-site"] || "").trim().toLowerCase();

  const originHeader = String(req?.headers?.origin || "").trim();
  let sourceOrigin = "";
  if (originHeader) {
    if (originHeader.toLowerCase() === "null") return false;
    try {
      const u = new URL(originHeader);
      if (u.protocol !== "http:" && u.protocol !== "https:") return false;
      sourceOrigin = u.origin;
    } catch {
      return false;
    }
  } else {
    const referer = String(req?.headers?.referer || "").trim();
    if (referer) {
      try {
        const u = new URL(referer);
        if (u.protocol !== "http:" && u.protocol !== "https:") return false;
        sourceOrigin = u.origin;
      } catch {
        return false;
      }
    }
  }

  if (secFetchSite === "cross-site" && (!sourceOrigin || !CORS_ALLOWLIST.has(sourceOrigin))) {
    return false;
  }

  if (!sourceOrigin) {
    // Never silently accept missing Origin/Referer in production
    if (isProd) return false;
    if (requireBrowserOrigin) {
      const ua = String(req?.headers?.["user-agent"] || "");
      const hasBrowserMetadata =
        Boolean(req?.headers?.["sec-fetch-site"]) ||
        /Mozilla\/5\.0/i.test(ua);
      if (hasBrowserMetadata) return false;
    }
    return true;
  }

  if (CORS_ALLOWLIST.has(sourceOrigin)) return true;

  const configuredBase = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configuredBase) {
    try {
      return new URL(configuredBase).origin === sourceOrigin;
    } catch {
      return false;
    }
  }

  // Never fall back to untrusted Host header in production
  if (isProd) {
    return false;
  }

  const rawHost = String(req?.headers?.host || "").trim();
  if (!rawHost) return false;
  let parsedOrigin;
  let candidateHost;
  try {
    parsedOrigin = new URL(sourceOrigin);
    candidateHost = new URL(`http://${rawHost}`);
  } catch {
    return false;
  }
  const hostname = candidateHost.hostname.toLowerCase();
  const isLoopback =
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  const isE2bPreview = /^[0-9]+-[a-z0-9-]+\.e2b\.app$/.test(hostname);
  const devAllowlist = new Set(
    String(process.env.ALLOWED_DEV_HOSTS || "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
  if (!isLoopback && !isE2bPreview && !devAllowlist.has(hostname)) {
    throw new BadRequestError(
      "Untrusted Host header rejected. Configure PUBLIC_BASE_URL or ALLOWED_DEV_HOSTS.",
      400,
      "untrusted_host_header",
    );
  }
  return parsedOrigin.host.toLowerCase() === candidateHost.host.toLowerCase();
}

// ---------------------------------------------------------------------------
// Pure-Node Two-Pass Bounded ZIP Extractor
// Blocks Overlapping Ranges, Duplicate Offsets, Small-Entry Bombs & Tenant Cap Overflows
// ---------------------------------------------------------------------------
function inflateSliceBounded(
  compressedSlice,
  compSize,
  seenCompressedBytes,
  addTotalBytes,
  initialTenantBytes,
  maxTenantDiskBytes,
) {
  return new Promise((resolvePromise, rejectPromise) => {
    const inflater = createInflateRaw();
    const chunks = [];
    let entryBytes = 0;
    let failed = false;

    const fail = (msg, statusCode = 400) => {
      if (failed) return;
      failed = true;
      inflater.destroy();
      rejectPromise(new BadRequestError(msg, statusCode));
    };

    inflater.on("data", (chunk) => {
      if (failed) return;
      entryBytes += chunk.length;
      const nextTotal = addTotalBytes(chunk.length);

      if (entryBytes > MAX_ZIP_SINGLE_BYTES) {
        fail(`ZIP entry exceeds ${MAX_ZIP_SINGLE_BYTES} byte uncompressed limit.`, 400);
        return;
      }
      if (nextTotal > MAX_ZIP_TOTAL_BYTES) {
        fail(`ZIP archive exceeds ${MAX_ZIP_TOTAL_BYTES} byte total uncompressed limit.`, 400);
        return;
      }
      if (initialTenantBytes + nextTotal > maxTenantDiskBytes) {
        fail("Workspace storage limit (128 MiB) exceeded during archive extraction.", 429);
        return;
      }
      if (entryBytes > 4096 && entryBytes / Math.max(1, compSize) > MAX_ZIP_RATIO) {
        fail("Suspicious high-ratio ZIP entry compression detected (zip bomb blocked).", 400);
        return;
      }
      if (nextTotal > 16_384 && nextTotal / Math.max(1, seenCompressedBytes) > MAX_ZIP_RATIO) {
        fail("Suspicious archive-wide ZIP compression ratio detected (zip bomb blocked).", 400);
        return;
      }
      chunks.push(chunk);
    });

    inflater.on("end", () => {
      if (!failed) resolvePromise(Buffer.concat(chunks));
    });

    inflater.on("error", () => {
      fail("Corrupt or invalid DEFLATE stream inside ZIP archive.", 400);
    });

    inflater.end(compressedSlice);
  });
}

export async function extractZipSafely(zipPath, destDir, options = {}) {
  const initialTenantBytes = Math.max(0, Number(options.initialTenantBytes || 0));
  const maxTenantDiskBytes = Math.max(
    1024,
    Number(options.maxTenantDiskBytes || MAX_TENANT_UPLOAD_BYTES),
  );

  mkdirSync(destDir, { recursive: true, mode: 0o700 });
  const destReal = realpathSync(destDir);
  const zipBuf = readFileSync(zipPath);

  if (zipBuf.length < 22) {
    throw new BadRequestError("Invalid or truncated ZIP archive.", 400);
  }

  // Locate End of Central Directory (EOCD) signature 0x06054b50
  let eocdOffset = -1;
  const minEocd = Math.max(0, zipBuf.length - 65_557);
  for (let i = zipBuf.length - 22; i >= minEocd; i -= 1) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new BadRequestError("Invalid ZIP archive (missing central directory).", 400);
  }

  const diskNum = zipBuf.readUInt16LE(eocdOffset + 4);
  const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
  const cdSize = zipBuf.readUInt32LE(eocdOffset + 12);
  const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);

  if (diskNum !== 0 || totalEntries === 0xffff || cdOffset === 0xffffffff) {
    throw new BadRequestError("Multi-disk or Zip64 archives are not supported.", 400);
  }
  if (totalEntries > MAX_ZIP_ENTRIES) {
    throw new BadRequestError(`ZIP archive exceeds maximum of ${MAX_ZIP_ENTRIES} entries.`, 400);
  }
  if (cdOffset + cdSize > eocdOffset) {
    throw new BadRequestError("Corrupt ZIP central directory bounds.", 400);
  }

  // Pass 1: Validate all Central Directory & Local File Headers + verify disjoint byte ranges
  const plannedEntries = [];
  const seenOffsets = new Set();
  const seenTargets = new Set();
  const byteRanges = [];

  let pos = cdOffset;
  for (let idx = 0; idx < totalEntries; idx += 1) {
    if (pos + 46 > eocdOffset || zipBuf.readUInt32LE(pos) !== 0x02014b50) {
      throw new BadRequestError("Corrupt ZIP central directory entry.", 400);
    }

    const flags = zipBuf.readUInt16LE(pos + 8);
    const method = zipBuf.readUInt16LE(pos + 10);
    const expectedCrc = zipBuf.readUInt32LE(pos + 16);
    const compSize = zipBuf.readUInt32LE(pos + 20);
    const uncompHeaderSize = zipBuf.readUInt32LE(pos + 24);
    const nameLen = zipBuf.readUInt16LE(pos + 28);
    const extraLen = zipBuf.readUInt16LE(pos + 30);
    const commentLen = zipBuf.readUInt16LE(pos + 32);
    const externalAttrs = zipBuf.readUInt32LE(pos + 38);
    const localHeaderOffset = zipBuf.readUInt32LE(pos + 42);

    const nameEnd = pos + 46 + nameLen;
    if (nameEnd + extraLen + commentLen > eocdOffset) {
      throw new BadRequestError("Truncated ZIP central directory entry.", 400);
    }

    if ((flags & 0x0001) !== 0) {
      throw new BadRequestError("Encrypted ZIP entries are not permitted.", 400);
    }
    if ((flags & 0x0008) !== 0) {
      throw new BadRequestError("Streaming data-descriptor ZIP entries are not permitted.", 400);
    }

    const unixFileType = (externalAttrs >>> 16) & 0o170000;
    if (unixFileType === 0o120000) {
      throw new BadRequestError("Symbolic links inside ZIP archives are forbidden.", 400);
    }

    const rawName = zipBuf.subarray(pos + 46, nameEnd).toString("utf8");
    pos = nameEnd + extraLen + commentLen;

    if (
      !rawName ||
      rawName.length > 255 ||
      rawName.includes("\0") ||
      rawName.startsWith("/") ||
      rawName.startsWith("\\") ||
      /^[a-zA-Z]:/.test(rawName)
    ) {
      throw new BadRequestError("Unsafe ZIP member filename rejected.", 400);
    }

    const normalizedRel = rawName.replace(/\\/g, "/");
    const isDirEntry = normalizedRel.endsWith("/") || unixFileType === 0o040000;
    const segments = normalizedRel.split("/").filter((s) => s.length > 0);
    if (segments.length === 0) continue;
    if (segments.length > 16 || segments.some((seg) => seg === "." || seg === "..")) {
      throw new BadRequestError("Path traversal sequence inside ZIP archive rejected.", 400);
    }

    const targetPath = resolve(destReal, ...segments);
    if (!(targetPath === destReal || targetPath.startsWith(destReal + sep))) {
      throw new BadRequestError("Unsafe ZIP member path rejected.", 400);
    }

    if (seenOffsets.has(localHeaderOffset)) {
      throw new BadRequestError(
        "Malformed or malicious ZIP archive: duplicate local header offset detected.",
        400,
      );
    }
    seenOffsets.add(localHeaderOffset);

    if (localHeaderOffset + 30 > cdOffset || zipBuf.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      throw new BadRequestError("Corrupt or out-of-bounds ZIP local file header.", 400);
    }
    const lfhFlags = zipBuf.readUInt16LE(localHeaderOffset + 6);
    const lfhMethod = zipBuf.readUInt16LE(localHeaderOffset + 8);
    const lfhNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);
    if ((lfhFlags & 0x0001) !== 0 || lfhMethod !== method) {
      throw new BadRequestError("Mismatched local and central directory ZIP headers.", 400);
    }

    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + compSize;
    if (dataStart < localHeaderOffset + 30 || dataEnd > cdOffset) {
      throw new BadRequestError("ZIP entry payload overlaps central directory or exceeds bounds.", 400);
    }

    byteRanges.push({ start: localHeaderOffset, end: Math.max(dataEnd, dataStart) });

    if (!isDirEntry) {
      if (seenTargets.has(targetPath)) {
        throw new BadRequestError("Duplicate output file path inside ZIP archive rejected.", 400);
      }
      seenTargets.add(targetPath);

      if (uncompHeaderSize > MAX_ZIP_SINGLE_BYTES) {
        throw new BadRequestError(`ZIP entry exceeds ${MAX_ZIP_SINGLE_BYTES} byte limit.`, 400);
      }
      if (method !== 0 && method !== 8) {
        throw new BadRequestError(`Unsupported ZIP compression method (${method}).`, 400);
      }
    }

    plannedEntries.push({
      isDirEntry,
      targetPath,
      method,
      expectedCrc,
      compSize,
      uncompHeaderSize,
      dataStart,
      dataEnd,
    });
  }

  // Verify strict non-overlap across all [localHeaderOffset, dataEnd) intervals (blocks Fifield overlapping bombs)
  byteRanges.sort((a, b) => a.start - b.start || a.end - b.end);
  for (let i = 1; i < byteRanges.length; i += 1) {
    if (byteRanges[i].start < byteRanges[i - 1].end) {
      throw new BadRequestError(
        "Overlapping ZIP entry byte ranges detected (overlapping zip bomb blocked).",
        400,
      );
    }
  }

  // Pass 2: Bounded extraction with synchronous pre-flight tenant byte reservation & real-time ratio enforcement
  const plannedUncompressedBytes = plannedEntries.reduce(
    (sum, e) => sum + (e.isDirEntry ? 0 : Number(e.uncompHeaderSize || 0)),
    0,
  );
  if (plannedUncompressedBytes > MAX_ZIP_TOTAL_BYTES) {
    throw new BadRequestError(`ZIP archive exceeds ${MAX_ZIP_TOTAL_BYTES} byte total uncompressed limit.`, 400);
  }
  if (typeof options.onReserveBytes === "function") {
    options.onReserveBytes(plannedUncompressedBytes);
  } else if (initialTenantBytes + plannedUncompressedBytes > maxTenantDiskBytes) {
    throw new BadRequestError(
      "Workspace storage limit (128 MiB) exceeded during archive extraction.",
      429,
      "tenant_storage_limit_exceeded",
    );
  }

  let totalExtractedBytes = 0;
  let seenCompressedBytes = 0;
  const liveBaseBytes = () =>
    typeof options.getLiveBaseTenantBytes === "function"
      ? options.getLiveBaseTenantBytes()
      : initialTenantBytes;
  const addTotalBytes = (n) => {
    totalExtractedBytes += n;
    if (typeof options.onProgressBytes === "function") {
      options.onProgressBytes(totalExtractedBytes);
    }
    return totalExtractedBytes;
  };

  for (const entry of plannedEntries) {
    if (entry.isDirEntry) {
      mkdirSync(entry.targetPath, { recursive: true, mode: 0o700 });
      const realDir = realpathSync(entry.targetPath);
      if (!(realDir === destReal || realDir.startsWith(destReal + sep))) {
        throw new BadRequestError("ZIP directory escaped extraction root.", 400);
      }
      continue;
    }

    seenCompressedBytes += Math.max(1, entry.compSize);
    const compressedSlice = zipBuf.subarray(entry.dataStart, entry.dataEnd);
    let outBuf;

    if (entry.method === 0) {
      const nextTotal = addTotalBytes(compressedSlice.length);
      if (compressedSlice.length > MAX_ZIP_SINGLE_BYTES || nextTotal > MAX_ZIP_TOTAL_BYTES) {
        throw new BadRequestError("ZIP archive exceeds uncompressed byte limits.", 400);
      }
      if (liveBaseBytes() + nextTotal > maxTenantDiskBytes) {
        throw new BadRequestError(
          "Workspace storage limit (128 MiB) exceeded during archive extraction.",
          429,
          "tenant_storage_limit_exceeded",
        );
      }
      outBuf = Buffer.from(compressedSlice);
    } else {
      outBuf = await inflateSliceBounded(
        compressedSlice,
        entry.compSize,
        seenCompressedBytes,
        addTotalBytes,
        liveBaseBytes(),
        maxTenantDiskBytes,
      );
    }

    if (outBuf.length !== entry.uncompHeaderSize) {
      throw new BadRequestError("ZIP entry uncompressed size mismatch.", 400);
    }
    if (crc32(outBuf) !== entry.expectedCrc) {
      throw new BadRequestError("ZIP entry CRC-32 integrity check failed.", 400);
    }

    const parentDir = dirname(entry.targetPath);
    mkdirSync(parentDir, { recursive: true, mode: 0o700 });
    const realParent = realpathSync(parentDir);
    if (!(realParent === destReal || realParent.startsWith(destReal + sep))) {
      throw new BadRequestError("ZIP parent path escaped extraction root.", 400);
    }
    if (existsSync(entry.targetPath) && lstatSync(entry.targetPath).isSymbolicLink()) {
      throw new BadRequestError("Refusing to overwrite symlink inside extraction directory.", 400);
    }
    writeFileSync(entry.targetPath, outBuf, { mode: 0o600 });
  }

  return totalExtractedBytes;
}

// ---------------------------------------------------------------------------
// Tenant-Isolated Upload Storage, Atomic In-Flight Byte Reservations & Reaper
// ---------------------------------------------------------------------------
/** @type {Map<string, { tenantId: string, bytes: number, excludeDir: string | null }>} */
const activeTenantUploadReservations = new Map();

function getTenantReservedBytes(tenantId, ignoreReservationId = null) {
  let sum = 0;
  for (const [id, rec] of activeTenantUploadReservations.entries()) {
    if (id !== ignoreReservationId && rec.tenantId === tenantId) {
      sum += Number(rec.bytes || 0);
    }
  }
  return sum;
}

function getAllActiveExcludedDirs() {
  const out = new Set();
  for (const rec of activeTenantUploadReservations.values()) {
    if (rec.excludeDir) {
      out.add(resolve(rec.excludeDir));
    }
  }
  return out;
}

export function getActiveUploadReservationCount(tenantId = null) {
  if (!tenantId) return activeTenantUploadReservations.size;
  let count = 0;
  for (const rec of activeTenantUploadReservations.values()) {
    if (rec.tenantId === tenantId) count += 1;
  }
  return count;
}

function measureDirectoryBytes(dirPath, excludedDirs = null) {
  if (!existsSync(dirPath)) return 0;
  if (excludedDirs && excludedDirs.has(resolve(dirPath))) return 0;
  let total = 0;
  for (const name of readdirSync(dirPath)) {
    const fp = join(dirPath, name);
    if (excludedDirs && excludedDirs.has(resolve(fp))) continue;
    let fst;
    try {
      fst = lstatSync(fp);
    } catch {
      continue;
    }
    if (fst.isDirectory()) total += measureDirectoryBytes(fp, excludedDirs);
    else if (fst.isFile()) total += fst.size;
  }
  return total;
}

export function pruneTenantUploads(tenantDir, now = Date.now(), ttlMs = UPLOAD_TTL_MS) {
  if (!existsSync(tenantDir)) return 0;
  let remainingBytes = 0;
  const excludedDirs = getAllActiveExcludedDirs();

  for (const slot of readdirSync(tenantDir)) {
    const slotPath = join(tenantDir, slot);
    if (excludedDirs.has(resolve(slotPath))) {
      continue;
    }
    let st;
    try {
      st = lstatSync(slotPath);
    } catch {
      continue;
    }
    if (now - st.mtimeMs > ttlMs) {
      // Never delete a slot directory that currently has an active in-flight unpack reservation
      const resolvedSlot = resolve(slotPath);
      const hasActiveChild = [...excludedDirs].some(
        (ex) => ex === resolvedSlot || ex.startsWith(resolvedSlot + sep),
      );
      if (!hasActiveChild) {
        rmSync(slotPath, { recursive: true, force: true });
        continue;
      }
    }
    if (st.isDirectory()) {
      remainingBytes += measureDirectoryBytes(slotPath, excludedDirs);
    } else if (st.isFile()) {
      remainingBytes += st.size;
    }
  }
  return remainingBytes;
}

function reserveTenantStorage(tenantId, bytesToReserve, { excludeDir = null, maxBytes = MAX_TENANT_UPLOAD_BYTES } = {}) {
  const tenantDir = join(engine.uploadsDir, tenantId);
  ensurePrivateDir(tenantDir);
  const diskBytes = pruneTenantUploads(tenantDir);
  const inFlightBytes = getTenantReservedBytes(tenantId);
  const requested = Math.max(0, Number(bytesToReserve || 0));

  if (diskBytes + inFlightBytes + requested > maxBytes) {
    throw new BadRequestError(
      "Workspace active upload storage cap (128 MiB) reached. Wait for active scans/uploads or TTL cleanup.",
      429,
      "tenant_storage_limit_exceeded",
    );
  }

  const reservationId = randomUUID();
  const record = {
    tenantId,
    bytes: requested,
    excludeDir: excludeDir ? resolve(excludeDir) : null,
  };
  activeTenantUploadReservations.set(reservationId, record);

  return {
    reservationId,
    diskBytesBefore: diskBytes + inFlightBytes,
    updateBytes(actualBytes) {
      const next = Math.max(record.bytes, Number(actualBytes || 0));
      const latestDisk = pruneTenantUploads(tenantDir);
      const otherReserved = getTenantReservedBytes(tenantId, reservationId);
      if (latestDisk + otherReserved + next > maxBytes) {
        throw new BadRequestError(
          "Workspace active upload storage cap (128 MiB) exceeded during archive extraction.",
          429,
          "tenant_storage_limit_exceeded",
        );
      }
      record.bytes = next;
    },
    getLiveBaseBytes() {
      return pruneTenantUploads(tenantDir) + getTenantReservedBytes(tenantId, reservationId);
    },
    release() {
      activeTenantUploadReservations.delete(reservationId);
    },
  };
}

export async function runHousekeeping({ now = Date.now(), uploadTtlMs = UPLOAD_TTL_MS, rlIdleMs } = {}) {
  if (existsSync(engine.uploadsDir)) {
    for (const tenantId of readdirSync(engine.uploadsDir)) {
      const tDir = join(engine.uploadsDir, tenantId);
      try {
        if (lstatSync(tDir).isDirectory()) {
          pruneTenantUploads(tDir, now, uploadTtlMs);
        }
      } catch {
        // ignore concurrent deletion
      }
    }
  }
  const reapedEnvs = await engine.reapIdleEnvironments(rlIdleMs);
  billing.pruneExpiredRecords();
  return { reaped_rl_environments: reapedEnvs };
}

function saveTenantUpload(tenantId, filename, fileBuffer) {
  if (!fileBuffer || fileBuffer.length === 0) {
    throw new BadRequestError("Uploaded artifact cannot be empty.", 400);
  }
  if (fileBuffer.length > MAX_UPLOAD_BYTES) {
    throw new PayloadTooLargeError(MAX_UPLOAD_BYTES);
  }

  const tenantDir = join(engine.uploadsDir, tenantId);
  ensurePrivateDir(tenantDir);
  const reservation = reserveTenantStorage(tenantId, fileBuffer.length);
  const uploadId = `${Date.now()}-${randomBytes(6).toString("hex")}`;
  const uploadSlot = join(tenantDir, uploadId);
  try {
    ensurePrivateDir(uploadSlot);
    const safeName = sanitizeFilename(filename);
    const diskPath = join(uploadSlot, safeName);
    writeFileSync(diskPath, fileBuffer, { mode: 0o600 });

    return {
      filename: safeName,
      bytes: fileBuffer.length,
      upload_id: uploadId,
      saved_path: `upload://${uploadId}/${safeName}`,
    };
  } catch (err) {
    rmSync(uploadSlot, { recursive: true, force: true });
    throw err;
  } finally {
    reservation.release();
  }
}

function resolveTenantUploadPath(tenantId, savedPathInput) {
  const raw = String(savedPathInput || "").trim();
  if (!raw.startsWith("upload://")) {
    throw new BadRequestError("Invalid or unauthorized upload reference.", 403);
  }
  const rest = raw.slice("upload://".length);
  const slashIdx = rest.indexOf("/");
  if (slashIdx <= 0) {
    throw new BadRequestError("Malformed upload reference.", 400);
  }
  const uploadId = rest.slice(0, slashIdx);
  const filePart = rest.slice(slashIdx + 1);
  if (
    !/^[0-9]{13}-[a-f0-9]{12}$/.test(uploadId) ||
    !filePart ||
    filePart.includes("/") ||
    filePart.includes("\\") ||
    filePart.includes("..")
  ) {
    throw new BadRequestError("Malformed upload reference.", 400);
  }

  const tenantDir = join(engine.uploadsDir, tenantId);
  if (!existsSync(tenantDir)) {
    throw new BadRequestError("Upload not found in active workspace.", 404);
  }
  pruneTenantUploads(tenantDir);
  const tenantReal = realpathSync(tenantDir);
  const candidate = resolve(tenantReal, uploadId, sanitizeFilename(filePart));
  if (!candidate.startsWith(tenantReal + sep) || !existsSync(candidate)) {
    throw new BadRequestError("Upload not found in active workspace.", 404);
  }
  const lst = lstatSync(candidate);
  if (!lst.isFile() || lst.isSymbolicLink()) {
    throw new BadRequestError("Invalid uploaded artifact type.", 400);
  }
  const realCandidate = realpathSync(candidate);
  if (!realCandidate.startsWith(tenantReal + sep)) {
    throw new BadRequestError("Upload path out of workspace scope.", 403);
  }
  return realCandidate;
}

/**
 * Prepares an uploaded JS or ZIP target AFTER scan quota has been reserved.
 * Returns `{ targetPath, cleanup }` where `cleanup()` deletes any temporary unpacked directory.
 */
async function prepareUploadedXrayTarget(tenantId, candidate) {
  const lower = candidate.toLowerCase();
  if (lower.endsWith(".zip")) {
    const unpackedDir = join(dirname(candidate), `unpacked-${randomUUID()}`);
    let reservation = null;
    try {
      await extractZipSafely(candidate, unpackedDir, {
        maxTenantDiskBytes: MAX_TENANT_UPLOAD_BYTES,
        onReserveBytes(plannedBytes) {
          reservation = reserveTenantStorage(tenantId, plannedBytes, {
            excludeDir: unpackedDir,
            maxBytes: MAX_TENANT_UPLOAD_BYTES,
          });
        },
        onProgressBytes(actualExtractedBytes) {
          reservation?.updateBytes(actualExtractedBytes);
        },
        getLiveBaseTenantBytes() {
          return reservation ? reservation.getLiveBaseBytes() : 0;
        },
      });
    } catch (err) {
      reservation?.release();
      rmSync(unpackedDir, { recursive: true, force: true });
      throw err;
    }

    let cleaned = false;
    return {
      targetPath: unpackedDir,
      cleanup: () => {
        if (cleaned) return;
        cleaned = true;
        try {
          rmSync(unpackedDir, { recursive: true, force: true });
        } finally {
          reservation?.release();
        }
      },
    };
  }
  if (lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) {
    const slotDir = dirname(candidate);
    const pkgPath = join(slotDir, "package.json");
    if (!existsSync(pkgPath)) {
      writeFileSync(
        pkgPath,
        JSON.stringify(
          {
            name: "uploaded-js-artifact",
            version: "1.0.0",
            main: basename(candidate),
          },
          null,
          2,
        ),
        { mode: 0o600 },
      );
    }
    return { targetPath: slotDir, cleanup: () => {} };
  }
  return { targetPath: candidate, cleanup: () => {} };
}

// ---------------------------------------------------------------------------
// Strict Separation: Interactive Browser Session Auth vs Headless /api/v1 Keys
// ---------------------------------------------------------------------------
function requireBrowserSessionAuth(req, res) {
  const sessionCtx = billing.resolveSessionContext(req);
  if (sessionCtx) {
    const method = String(req.method || "GET").toUpperCase();
    const isStateChanging = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
    if (isStateChanging) {
      if (!isRequestOriginAllowed(req)) {
        sendJson(req, res, 403, {
          ok: false,
          error: {
            code: "cross_origin_forbidden",
            message: "Cross-origin state-changing cookie request blocked.",
          },
        });
        return null;
      }
      if (!billing.verifyCsrfToken(sessionCtx, req)) {
        sendJson(req, res, 403, {
          ok: false,
          error: {
            code: "csrf_validation_failed",
            message: "Missing or invalid X-CSRF-Token header for cookie-authenticated session.",
          },
        });
        return null;
      }
    }
    return {
      tenant: sessionCtx.tenant,
      authType: "session",
      csrfToken: sessionCtx.csrfToken,
    };
  }

  // Explicitly block Bearer CI/API keys from interactive browser, billing, portal, license & payment endpoints
  const authHeader = String(req.headers?.authorization || "").trim();
  if (/^Bearer\s+\S+/i.test(authHeader)) {
    const apiKeyAuth = billing.authenticateApiKey(req);
    if (apiKeyAuth) {
      sendJson(req, res, 403, {
        ok: false,
        error: {
          code: "api_key_forbidden",
          message:
            "Bearer API keys are restricted to authorized headless /api/v1/* endpoints. Sign in via an interactive browser session.",
        },
      });
      return null;
    }
  }

  sendJson(req, res, 401, {
    ok: false,
    error: {
      code: "unauthorized",
      message: "Interactive workspace browser session required. Sign in to continue.",
    },
  });
  return null;
}

/** Per-license-hash async mutex preventing concurrent duplicate upstream seat activations */
const inFlightLicenseLocks = new Map();

async function withLicenseMutex(licenseKey, fn) {
  const keyHash = createHash("sha256").update(String(licenseKey || "").trim()).digest("hex");
  const prev = inFlightLicenseLocks.get(keyHash) || Promise.resolve();
  let releaseLock;
  const next = new Promise((r) => {
    releaseLock = r;
  });
  const chained = prev.then(() => next, () => next);
  inFlightLicenseLocks.set(keyHash, chained);
  await prev.catch(() => {});
  try {
    return await fn();
  } finally {
    releaseLock();
    if (inFlightLicenseLocks.get(keyHash) === chained) {
      inFlightLicenseLocks.delete(keyHash);
    }
  }
}

// ---------------------------------------------------------------------------
// Server-Side On-Chain USDT Receipt Verification Helper
// ---------------------------------------------------------------------------
function getRpcListForChain(chain) {
  const envKey = `ALPHASHIELD_RPC_URL_${chain.toUpperCase()}`;
  const custom = String(process.env[envKey] || "").trim();
  if (custom) {
    return custom.split(",").map((s) => s.trim()).filter(Boolean);
  }
  return OFFICIAL_STABLECOINS[chain]?.defaultRpcs || [];
}

async function rpcCall(rpcUrls, method, params) {
  for (const rpcUrl of rpcUrls) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6500);
    try {
      const resp = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: ctrl.signal,
      });
      if (!resp.ok) continue;
      const json = await resp.json();
      if (json && "result" in json && json.result !== null) {
        return json.result;
      }
    } catch {
      // try next RPC
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

export function decodeRlDownloadEnvId(rawSegment) {
  let decoded;
  try {
    decoded = decodeURIComponent(String(rawSegment ?? ""));
  } catch {
    throw new BadRequestError(
      "Malformed percent-encoding in RL download URL.",
      400,
      "malformed_url_encoding",
    );
  }
  const trimmed = decoded.trim();
  if (!trimmed || trimmed.includes("\0") || trimmed.includes("/") || trimmed.includes("\\")) {
    throw new BadRequestError(
      "Invalid RL environment identifier in download URL.",
      400,
      "invalid_rl_env_id",
    );
  }
  return trimmed;
}

export const server = createHttpServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      res.writeHead(204, buildSecurityHeaders(req));
      res.end();
      return;
    }

    let url;
    try {
      url = new URL(req.url || "/", "http://studio.local");
    } catch {
      throw new BadRequestError("Malformed request URL.", 400, "malformed_url");
    }
    const pathname = url.pathname;
    const clientIp = getClientIp(req);

    // -----------------------------------------------------------------------
    // Unhardened Legacy Side-Apps Explicitly Unmounted (Return 404)
    // -----------------------------------------------------------------------
    if (
      pathname === "/solidcraft" ||
      pathname.startsWith("/solidcraft/") ||
      pathname === "/canvix" ||
      pathname.startsWith("/canvix/")
    ) {
      const notFoundBody = Buffer.from("Not Found", "utf8");
      res.writeHead(
        404,
        buildSecurityHeaders(req, {
          "content-type": "text/plain; charset=utf-8",
          "content-length": notFoundBody.length,
          "cache-control": "no-store",
        }),
      );
      res.end(notFoundBody);
      return;
    }

    // -----------------------------------------------------------------------
    // System, Health & Public CI Script Distribution Endpoints
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/health") {
      await engine.init();
      sendJson(req, res, 200, {
        ok: true,
        status: "healthy",
        rea_version: "6.8.0",
        mcp_tools: engine.toolCount,
        uptime_sec: Math.round(process.uptime()),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/ci/shipgate-cli.mjs") {
      const cliBytes = readFileSync(join(STUDIO_ROOT, "ci/shipgate-cli.mjs"));
      res.writeHead(
        200,
        buildSecurityHeaders(req, {
          "content-type": "application/javascript; charset=utf-8",
          "content-length": cliBytes.length,
          "content-disposition": 'attachment; filename="shipgate-cli.mjs"',
        }),
      );
      res.end(cliBytes);
      return;
    }

    if (req.method === "GET" && pathname === "/api/ci/github-action.yml") {
      const ymlBytes = readFileSync(join(STUDIO_ROOT, "ci/github-action-workflow.yml"));
      res.writeHead(
        200,
        buildSecurityHeaders(req, {
          "content-type": "text/yaml; charset=utf-8",
          "content-length": ymlBytes.length,
          "content-disposition": 'attachment; filename="rea-shipgate.yml"',
        }),
      );
      res.end(ymlBytes);
      return;
    }

    // -----------------------------------------------------------------------
    // Signed Webhook Endpoints (HMAC-SHA256 + Timestamp + Event Replay Guard)
    // -----------------------------------------------------------------------
    if (
      req.method === "POST" &&
      (pathname === "/api/webhooks/stripe" || pathname === "/api/billing/webhook")
    ) {
      if (!enforceRateLimit(apiLimiter, `wh:stripe:${clientIp}`, req, res)) return;
      const rawBuf = await readBodyBuffer(req, 1024 * 1024);
      const sig = req.headers["stripe-signature"] || "";
      const handled = billing.verifyAndHandleStripeWebhook(rawBuf, sig);
      sendJson(req, res, handled.ok ? 200 : handled.status || 400, handled);
      return;
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/webhooks/kelviq" || pathname === "/api/kelviq/webhook")
    ) {
      if (!enforceRateLimit(apiLimiter, `wh:kelviq:${clientIp}`, req, res)) return;
      const rawBuf = await readBodyBuffer(req, 1024 * 1024);
      try {
        await kelviq.init();
        const { event, webhookId } = kelviq.verifyAndParseWebhook(rawBuf, req.headers);
        if (webhookId && billing.isWebhookProcessed("kelviq", webhookId)) {
          sendJson(req, res, 200, { ok: true, duplicate: true, webhook_id: webhookId });
          return;
        }

        const type = String(event?.type || event?.event || "");
        const data = event?.data || event?.object || event || {};
        const meta = data?.metadata || event?.metadata || {};
        const tenantId = meta.tenant_id || data.customerId || data.customer_id;
        const planRaw =
          meta.kelviq_plan || meta.plan_id || data.planIdentifier || data?.plan?.identifier || "";
        const subscriptionId =
          data.subscriptionId ||
          data.subscription_id ||
          (typeof data.id === "string" && data.id.startsWith("sub") ? data.id : null);
        const expiresAt = data.currentPeriodEnd || data.expiresAt || data.expires_on || null;
        const chargePeriod = data.chargePeriod || meta.charge_period || "MONTHLY";

        const durationMs =
          String(chargePeriod).toUpperCase() === "YEARLY"
            ? 366 * 24 * 60 * 60 * 1000
            : 31 * 24 * 60 * 60 * 1000;
        const computedExpiresAt =
          expiresAt || new Date(Date.now() + durationMs).toISOString();

        if (/checkout\.completed|subscription\.(created|activated|updated)/i.test(type) && tenantId) {
          const entitlement = kelviq.resolveEntitlementFromKelviq(planRaw);
          if (!entitlement) {
            sendJson(req, res, 400, {
              ok: false,
              error: {
                code: "unknown_kelviq_plan",
                message: "Webhook payload is missing a recognized Kelviq plan identifier.",
              },
            });
            return;
          }
          const provisioned =
            entitlement.product === "studio"
              ? billing.applyPlanProvisioning(tenantId, entitlement.plan_id, {
                  source: "kelviq_webhook",
                  kelviq_subscription_id: subscriptionId || undefined,
                  expires_at: computedExpiresAt,
                })
              : billing.applyAlphaShieldProvisioning(tenantId, entitlement.plan_id, {
                  source: "kelviq_webhook",
                  kelviq_subscription_id: subscriptionId || undefined,
                  expires_at: computedExpiresAt,
                });
          if (!provisioned.ok) {
            sendJson(req, res, provisioned.status || 400, provisioned);
            return;
          }
          if (webhookId) billing.markWebhookProcessed("kelviq", webhookId);
          sendJson(req, res, 200, { ok: true, event_type: type, provisioned });
          return;
        }

        if (
          /subscription\.(cancelled|canceled|expired)|invoice\.payment_failed/i.test(type) &&
          (tenantId || subscriptionId)
        ) {
          const entitlement = planRaw ? kelviq.resolveEntitlementFromKelviq(planRaw) : null;
          if (planRaw && !entitlement && !subscriptionId) {
            sendJson(req, res, 400, {
              ok: false,
              error: {
                code: "unknown_kelviq_plan",
                message: "Unrecognized Kelviq plan identifier in cancellation webhook.",
              },
            });
            return;
          }
          const downgraded = billing.handleKelviqTermination({
            subscriptionId,
            tenantId,
            resolvedEntitlement: entitlement,
            source: "kelviq_subscription_ended",
          });
          if (!downgraded.ok) {
            sendJson(req, res, downgraded.status || 400, downgraded);
            return;
          }
          if (webhookId) billing.markWebhookProcessed("kelviq", webhookId);
          sendJson(req, res, 200, { ok: true, event_type: type, downgraded });
          return;
        }

        if (webhookId) billing.markWebhookProcessed("kelviq", webhookId);
        sendJson(req, res, 200, { ok: true, ignored: type });
      } catch (err) {
        sendJson(req, res, 400, {
          ok: false,
          error: { message: err instanceof Error ? err.message : "Kelviq webhook verification failed" },
        });
      }
      return;
    }

    // -----------------------------------------------------------------------
    // Bootstrap Metadata (Zero Secret Leakage, Zero Cross-Tenant Data)
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/bootstrap") {
      await engine.init();
      await kelviq.init();
      const sessionCtx = billing.resolveSessionContext(req);
      const sessionTenant = sessionCtx?.tenant || null;
      sendJson(req, res, 200, {
        ok: true,
        authenticated: Boolean(sessionTenant),
        csrf_token: sessionCtx?.csrfToken || null,
        product: {
          name: "REA Cloud Studio",
          tagline: "Enterprise Reverse-Engineering, Release Gate & RL Environment Factory",
          rea_version: "6.8.0",
          mcp_tools_available: engine.toolCount,
        },
        tenant: sessionTenant
          ? billing.sanitizeTenant(sessionTenant, { kelviqConfigured: kelviq.isConfigured })
          : null,
        plans: Object.values(PLANS),
        samples: {
          electron: samples.electronTargets.map(({ path: _p, ...rest }) => rest),
          binary: samples.binaryTargets.map(({ path: _p, ...rest }) => rest),
          har: samples.harTargets.map(({ path: _p, ...rest }) => rest),
        },
        evidence_recent: sessionTenant ? engine.listEvidence(sessionTenant.id).slice(0, 25) : [],
        api_keys: sessionTenant ? billing.listTenantKeys(sessionTenant.id) : [],
      });
      return;
    }

    // -----------------------------------------------------------------------
    // Multi-Tenant Auth (Email+IP + Global Circuit Breaker + HttpOnly Cookie + CSRF)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/auth/register") {
      if (!isRequestOriginAllowed(req, { requireBrowserOrigin: true })) {
        sendJson(req, res, 403, {
          ok: false,
          error: { code: "cross_origin_forbidden", message: "Cross-origin or untrusted-origin auth request forbidden." },
        });
        return;
      }
      if (!enforceRateLimit(authGlobalBreaker, "global:auth", req, res)) return;
      const body = await readJsonBody(req, 16 * 1024);
      const emailNorm = String(body.email || "").trim().toLowerCase().slice(0, 160) || "anon";
      if (!enforceRateLimit(authPairLimiter, `reg:${clientIp}:${emailNorm}`, req, res)) return;
      if (!enforceRateLimit(authAccountLimiter, `regacct:${emailNorm}`, req, res)) return;

      const out = billing.register(body);
      if (!out.ok) {
        sendJson(req, res, 400, out);
        return;
      }
      const cookieHeader = buildSessionSetCookie(
        out._cookie_session_token,
        out._cookie_max_age_sec || 7 * 24 * 60 * 60,
      );
      const { _cookie_session_token: _tok, _cookie_max_age_sec: _age, ...publicOut } = out;
      sendJson(req, res, 200, publicOut, { "set-cookie": cookieHeader });
      return;
    }

    if (req.method === "POST" && pathname === "/api/auth/login") {
      if (!isRequestOriginAllowed(req, { requireBrowserOrigin: true })) {
        sendJson(req, res, 403, {
          ok: false,
          error: { code: "cross_origin_forbidden", message: "Cross-origin or untrusted-origin auth request forbidden." },
        });
        return;
      }
      if (!enforceRateLimit(authGlobalBreaker, "global:auth", req, res)) return;
      const body = await readJsonBody(req, 16 * 1024);
      const emailNorm = String(body.email || "").trim().toLowerCase().slice(0, 160) || "anon";
      if (!enforceRateLimit(authPairLimiter, `login:${clientIp}:${emailNorm}`, req, res)) return;
      if (!enforceRateLimit(authAccountLimiter, `loginacct:${emailNorm}`, req, res)) return;

      const out = billing.login(body);
      if (!out.ok) {
        sendJson(req, res, 401, out);
        return;
      }
      const cookieHeader = buildSessionSetCookie(
        out._cookie_session_token,
        out._cookie_max_age_sec || 7 * 24 * 60 * 60,
      );
      const { _cookie_session_token: _tok, _cookie_max_age_sec: _age, ...publicOut } = out;
      sendJson(req, res, 200, publicOut, { "set-cookie": cookieHeader });
      return;
    }

    if (req.method === "POST" && pathname === "/api/auth/logout") {
      const sessionCtx = billing.resolveSessionContext(req);
      if (sessionCtx) {
        if (!isRequestOriginAllowed(req) || !billing.verifyCsrfToken(sessionCtx, req)) {
          sendJson(req, res, 403, {
            ok: false,
            error: { code: "csrf_validation_failed", message: "CSRF validation failed on logout." },
          });
          return;
        }
      }
      const out = billing.logout(req);
      sendJson(req, res, 200, out, {
        "set-cookie": buildClearSessionCookie(),
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/auth/me") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      await kelviq.init();
      sendJson(req, res, 200, {
        ok: true,
        authenticated: true,
        csrf_token: auth.csrfToken || null,
        tenant: billing.sanitizeTenant(auth.tenant, { kelviqConfigured: kelviq.isConfigured }),
        plans: Object.values(PLANS),
        api_keys: billing.listTenantKeys(auth.tenant.id),
        billing_events: billing.listTenantBillingEvents(auth.tenant.id),
      });
      return;
    }

    // -----------------------------------------------------------------------
    // Stripe & Sandbox Billing Routes (Interactive Browser Session Only)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/billing/checkout") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `bill:${auth.tenant.id}`, req, res)) return;
      await kelviq.init();
      const body = await readJsonBody(req, 64 * 1024);
      const originUrl = resolvePublicOrigin(req);
      const out = await billing.createCheckoutSession(auth.tenant, body.plan_id, originUrl, {
        kelviqConfigured: kelviq.isConfigured,
      });
      sendJson(req, res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/billing/confirm-sandbox") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      await kelviq.init();
      if (!billing.isSandboxBillingAllowed({ kelviqConfigured: kelviq.isConfigured })) {
        sendJson(req, res, 403, {
          ok: false,
          error: {
            code: "sandbox_billing_disabled",
            message:
              "Sandbox self-provisioning is disabled. Plans are provisioned exclusively via verified webhooks.",
          },
        });
        return;
      }
      const body = await readJsonBody(req, 64 * 1024);
      const out = billing.applyPlanProvisioning(auth.tenant.id, body.plan_id, {
        source: "sandbox_checkout",
      });
      sendJson(req, res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    // -----------------------------------------------------------------------
    // Kelviq Merchant-of-Record Routes + AlphaShield Authenticated Endpoints
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/kelviq/status") {
      await kelviq.init();
      const sessionCtx = billing.resolveSessionContext(req);
      const sessionTenant = sessionCtx?.tenant || null;
      sendJson(req, res, 200, {
        ok: true,
        authenticated: Boolean(sessionTenant),
        csrf_token: sessionCtx?.csrfToken || null,
        kelviq: kelviq.statusSummary({ stripeConfigured: Boolean(billing.stripeSecretKey) }),
        tenant: sessionTenant
          ? billing.sanitizeTenant(sessionTenant, { kelviqConfigured: kelviq.isConfigured })
          : null,
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/checkout") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `kvq:${auth.tenant.id}`, req, res)) return;
      const body = await readJsonBody(req, 64 * 1024);
      const originUrl = resolvePublicOrigin(req);
      const out = await kelviq.createCheckoutSession({
        tenant: auth.tenant,
        planId: body.plan_id || "alphashield_pro",
        chargePeriod: body.charge_period || "MONTHLY",
        originUrl,
        stripeConfigured: Boolean(billing.stripeSecretKey),
      });
      sendJson(req, res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/portal") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(authPairLimiter, `portal:${auth.tenant.id}:${clientIp}`, req, res)) return;
      const out = await kelviq.createPortalSession({ tenant: auth.tenant });
      sendJson(req, res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/kelviq/license/activate") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(authPairLimiter, `lic:${auth.tenant.id}:${clientIp}`, req, res)) return;
      const body = await readJsonBody(req, 64 * 1024);
      const cleanKey = String(body.license_key || "").trim();
      if (!cleanKey) {
        sendJson(req, res, 400, { ok: false, error: { message: "Enter a valid license key." } });
        return;
      }

      await withLicenseMutex(cleanKey, async () => {
        // Reject cross-tenant sharing BEFORE contacting Kelviq or provisioning
        const existingBinding = billing.getLicenseBinding(cleanKey);
        if (existingBinding && existingBinding.tenant_id !== auth.tenant.id) {
          sendJson(req, res, 409, {
            ok: false,
            error: {
              code: "license_already_bound",
              message: "This license key is already bound to another workspace.",
            },
          });
          return;
        }

        const out = await kelviq.activateLicenseKey({
          licenseKey: cleanKey,
          tenant: auth.tenant,
          instanceName: body.instance_name || "alphashield-web",
          stripeConfigured: Boolean(billing.stripeSecretKey),
        });
        if (!out.ok) {
          sendJson(req, res, out.status || 400, out);
          return;
        }

        const provisioned = billing.bindAndProvisionLicense({
          tenantId: auth.tenant.id,
          licenseKey: cleanKey,
          product: out.product,
          planId: out.plan_id,
          instanceId: out.instance_id,
          expiresAt: out.expires_on,
        });
        if (!provisioned.ok) {
          sendJson(req, res, provisioned.status || 409, provisioned);
          return;
        }
        sendJson(req, res, 200, { ...out, tenant: provisioned.tenant });
      });
      return;
    }

    // -----------------------------------------------------------------------
    // Direct On-Chain USDT Payment Intent & Tenant-Bound Verification
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/alphashield/payment-intent") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(authPairLimiter, `payintent:${auth.tenant.id}:${clientIp}`, req, res)) {
        return;
      }
      if (!kelviq.isDirectUsdtEnabled || !kelviq.merchantWallet) {
        sendJson(req, res, 503, {
          ok: false,
          error: {
            code: "direct_usdt_disabled",
            message:
              "Direct on-chain USDT checkout is disabled on this server. Use Kelviq checkout or set ALPHASHIELD_ENABLE_DIRECT_USDT=true with ALPHASHIELD_MERCHANT_WALLET.",
          },
        });
        return;
      }

      const body = await readJsonBody(req, 32 * 1024);
      const chain = String(body.chain || "bsc").toLowerCase();
      if (!OFFICIAL_STABLECOINS[chain]) {
        sendJson(req, res, 400, { ok: false, error: { message: "Unsupported payment chain." } });
        return;
      }
      const requestedPlan =
        body.plan_id === "alphashield_whale" || body.plan_id === "whale"
          ? "alphashield_whale"
          : body.plan_id === "alphashield_pro" || !body.plan_id
            ? "alphashield_pro"
            : null;
      if (!requestedPlan) {
        sendJson(req, res, 400, { ok: false, error: { message: "Invalid AlphaShield plan_id." } });
        return;
      }
      const period = body.charge_period === "YEARLY" ? "YEARLY" : "MONTHLY";
      const payerWallet = String(body.payer_wallet || "").trim().toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(payerWallet)) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "invalid_payer_wallet",
            message: "Provide the 42-character 0x sender wallet address you will pay from.",
          },
        });
        return;
      }

      const tok = OFFICIAL_STABLECOINS[chain].tokens[0];
      const planMeta = ALPHASHIELD_PLANS[requestedPlan];
      const baseUsd = period === "YEARLY" ? planMeta.price_yearly_usd : planMeta.price_monthly_usd;
      const created = billing.createUsdtPaymentIntent({
        tenantId: auth.tenant.id,
        chain,
        payerWallet,
        planId: requestedPlan,
        chargePeriod: period,
        baseUsd,
        decimals: tok.decimals,
      });
      if (!created.ok) {
        sendJson(req, res, created.status || 400, created);
        return;
      }

      sendJson(req, res, 200, {
        ok: true,
        intent: created.intent,
        merchant_wallet: kelviq.merchantWallet,
        token_contract: tok.address,
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/alphashield/verify-tx") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(authPairLimiter, `txverify:${auth.tenant.id}:${clientIp}`, req, res)) return;

      const merchantWallet = kelviq.merchantWallet;
      if (!kelviq.isDirectUsdtEnabled || !merchantWallet) {
        sendJson(req, res, 503, {
          ok: false,
          error: {
            code: "direct_usdt_disabled",
            message: "Direct on-chain USDT verification is disabled on this server.",
          },
        });
        return;
      }

      const body = await readJsonBody(req, 64 * 1024);
      const intentId = String(body.intent_id || "").trim();
      const txHash = String(body.tx_hash || "").trim().toLowerCase();

      if (!intentId) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "payment_intent_required",
            message: "Create a tenant-bound payment intent before verifying a transaction.",
          },
        });
        return;
      }
      if (!/^0x[0-9a-f]{64}$/.test(txHash)) {
        sendJson(req, res, 400, {
          ok: false,
          error: { message: "Invalid 66-character 0x transaction hash." },
        });
        return;
      }

      const intent = billing.getPaymentIntent(intentId);
      if (!intent) {
        sendJson(req, res, 404, {
          ok: false,
          error: { code: "payment_intent_not_found", message: "Payment intent not found." },
        });
        return;
      }
      if (intent.tenant_id !== auth.tenant.id) {
        sendJson(req, res, 403, {
          ok: false,
          error: {
            code: "payment_intent_tenant_mismatch",
            message: "This payment intent belongs to a different workspace.",
          },
        });
        return;
      }
      if (intent.status === "redeemed") {
        sendJson(req, res, 409, {
          ok: false,
          error: { code: "intent_already_fulfilled", message: "Payment intent has already been redeemed." },
        });
        return;
      }
      if (intent.status !== "pending" || Date.parse(intent.expires_at) <= Date.now()) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "payment_intent_expired",
            message: "Payment intent has expired. Generate a new payment intent before paying.",
          },
        });
        return;
      }

      const chain = intent.chain;
      const chainCfg = OFFICIAL_STABLECOINS[chain];
      if (!chainCfg) {
        sendJson(req, res, 400, { ok: false, error: { message: "Unsupported payment chain." } });
        return;
      }
      if (body.chain && String(body.chain).trim().toLowerCase() !== chain) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "intent_chain_mismatch",
            message: `Transaction chain must match payment intent chain (${chain}).`,
          },
        });
        return;
      }
      if (billing.isTxHashConsumed(chain, txHash)) {
        sendJson(req, res, 409, {
          ok: false,
          error: {
            code: "tx_already_redeemed",
            message: "This transaction hash has already been redeemed.",
          },
        });
        return;
      }

      const rpcUrls = getRpcListForChain(chain);
      const [rpcChainId, receipt, headBlockHex] = await Promise.all([
        rpcCall(rpcUrls, "eth_chainId", []),
        rpcCall(rpcUrls, "eth_getTransactionReceipt", [txHash]),
        rpcCall(rpcUrls, "eth_blockNumber", []),
      ]);

      if (rpcChainId === null || rpcChainId === undefined || String(rpcChainId).trim() === "") {
        sendJson(req, res, 502, {
          ok: false,
          error: {
            code: "rpc_chain_id_unavailable",
            message: `Unable to verify RPC eth_chainId for ${chain}. Retry when RPC is healthy.`,
          },
        });
        return;
      }

      {
        const expectedId = BigInt(chainCfg.chainIdHex);
        let observedId = -1n;
        try {
          observedId = BigInt(String(rpcChainId).trim());
        } catch {
          sendJson(req, res, 502, {
            ok: false,
            error: {
              code: "rpc_chain_id_unavailable",
              message: `Invalid eth_chainId response from RPC endpoint for ${chain}.`,
            },
          });
          return;
        }
        if (observedId !== expectedId) {
          sendJson(req, res, 502, {
            ok: false,
            error: {
              code: "rpc_chain_id_mismatch",
              message: `RPC endpoint chainId mismatch for ${chain}.`,
            },
          });
          return;
        }
      }

      if (!receipt) {
        sendJson(req, res, 404, {
          ok: false,
          error: { message: "Transaction receipt not found on chain yet. Wait for block confirmation." },
        });
        return;
      }
      if (String(receipt.status || "").toLowerCase() !== "0x1") {
        sendJson(req, res, 400, { ok: false, error: { message: "Transaction reverted on-chain." } });
        return;
      }
      if (!receipt.blockNumber) {
        sendJson(req, res, 400, {
          ok: false,
          error: { message: "Transaction is still pending block inclusion." },
        });
        return;
      }

      let txBlockNum;
      let headBlockNum;
      try {
        txBlockNum = BigInt(String(receipt.blockNumber));
        headBlockNum = headBlockHex ? BigInt(String(headBlockHex)) : -1n;
      } catch {
        sendJson(req, res, 502, {
          ok: false,
          error: { code: "rpc_invalid_block_number", message: "Invalid block number returned by RPC." },
        });
        return;
      }

      const requiredConfirmations = chainCfg.minConfirmations;
      const confirmations = headBlockNum >= txBlockNum ? Number(headBlockNum - txBlockNum) : 0;
      if (headBlockNum < txBlockNum || confirmations < requiredConfirmations) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "insufficient_confirmations",
            chain,
            confirmations,
            required_confirmations: requiredConfirmations,
            message: `Transaction has ${confirmations}/${requiredConfirmations} required block confirmations on ${chain.toUpperCase()}. Wait for finality and retry.`,
          },
        });
        return;
      }

      const block = await rpcCall(rpcUrls, "eth_getBlockByNumber", [receipt.blockNumber, false]);
      if (
        receipt.blockHash &&
        block?.hash &&
        String(receipt.blockHash).toLowerCase() !== String(block.hash).toLowerCase()
      ) {
        sendJson(req, res, 409, {
          ok: false,
          error: {
            code: "reorg_detected",
            message: "Transaction receipt blockHash does not match canonical chain block.",
          },
        });
        return;
      }
      const blockTs = Number.parseInt(String(block?.timestamp || "0x0"), 16);
      const nowSec = Math.floor(Date.now() / 1000);
      const intentCreatedSec = Math.floor(Date.parse(intent.created_at) / 1000);
      if (
        !Number.isFinite(blockTs) ||
        blockTs <= 0 ||
        nowSec - blockTs > 86_400 ||
        blockTs < intentCreatedSec - 60
      ) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "tx_timestamp_out_of_window",
            message: "Transaction block timestamp does not match the active payment intent window.",
          },
        });
        return;
      }

      const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
      const expectedFromClean = intent.payer_wallet.toLowerCase().slice(2);
      const expectedToClean = merchantWallet.toLowerCase().slice(2);
      const expectedExactRaw = BigInt(intent.exact_raw_units);
      let matchedSymbol = null;

      for (const log of receipt.logs || []) {
        const logAddr = String(log.address || "").toLowerCase();
        const tok = OFFICIAL_STABLECOINS[chain].tokens.find((t) => t.address === logAddr);
        if (!tok) continue;
        if (String(log.topics?.[0] || "").toLowerCase() !== transferTopic) continue;

        const senderTopic = String(log.topics?.[1] || "").toLowerCase();
        const recipientTopic = String(log.topics?.[2] || "").toLowerCase();
        if (!/^0x0{24}[0-9a-f]{40}$/.test(senderTopic)) continue;
        if (!/^0x0{24}[0-9a-f]{40}$/.test(recipientTopic)) continue;
        if (senderTopic.slice(-40) !== expectedFromClean) continue;
        if (recipientTopic.slice(-40) !== expectedToClean) continue;

        const rawAmount = BigInt(log.data || "0x0");
        if (rawAmount === expectedExactRaw) {
          matchedSymbol = tok.symbol;
          break;
        }
      }

      if (!matchedSymbol) {
        sendJson(req, res, 400, {
          ok: false,
          error: {
            code: "intent_transfer_mismatch",
            message:
              "No ERC-20 USDT transfer matching your registered payer wallet, merchant wallet, and exact payment intent amount was found in this transaction.",
          },
        });
        return;
      }

      const redeemed = billing.redeemUsdtPaymentIntent({
        intentId: intent.id,
        tenantId: auth.tenant.id,
        chain,
        txHash,
        matchedSymbol,
      });
      if (!redeemed.ok) {
        sendJson(req, res, redeemed.status || 409, redeemed);
        return;
      }

      sendJson(req, res, 200, {
        ok: true,
        chain,
        token: matchedSymbol,
        plan_id: intent.plan_id,
        charge_period: intent.charge_period,
        intent_id: intent.id,
        expires_at: redeemed.expires_at,
        tenant: redeemed.tenant,
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/alphashield/evm-audit") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `evm:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req, 512 * 1024);
      const rawAddress = String(body.address || "").trim().toLowerCase();
      const chain = String(body.chain || "ethereum").trim().toLowerCase();
      let rawHex = String(body.bytecode || "").trim().replace(/^0x/i, "");

      const isAddressQuery = /^0x[0-9a-f]{40}$/.test(rawAddress);
      if (!rawHex && !isAddressQuery) {
        sendJson(req, res, 400, {
          ok: false,
          error: { message: "Provide valid hex contract bytecode or a 42-character 0x contract address." },
        });
        return;
      }
      if (rawHex && !/^[0-9a-fA-F]{8,200000}$/.test(rawHex)) {
        sendJson(req, res, 400, { ok: false, error: { message: "Provide valid hex contract bytecode." } });
        return;
      }

      const quota = billing.checkAndConsumeAlphaShieldQuota(auth.tenant);
      if (!quota.ok) {
        sendJson(req, res, quota.status || 402, quota);
        return;
      }

      if (!rawHex && isAddressQuery) {
        const rpcUrls = getRpcListForChain(chain);
        if (rpcUrls.length > 0) {
          const fetchedCode = await rpcCall(rpcUrls, "eth_getCode", [rawAddress, "latest"]);
          const cleaned = String(fetchedCode || "").trim().replace(/^0x/i, "");
          if (/^[0-9a-fA-F]{8,200000}$/.test(cleaned)) {
            rawHex = cleaned;
          }
        }
      }

      if (!rawHex) {
        await kelviq.reportScanUsage(auth.tenant.id, "contract-scans");
        sendJson(req, res, 200, {
          ok: true,
          mode: "address_assessment",
          address: rawAddress,
          chain,
          is_eoa_or_unfetched: true,
          panels: { evm: { functions: [] } },
          tenant: quota.tenant,
        });
        return;
      }

      const tenantScratch = join(engine.uploadsDir, auth.tenant.id);
      ensurePrivateDir(tenantScratch);
      const carrier = join(tenantScratch, `evm-${Date.now()}-${randomBytes(4).toString("hex")}.hex`);
      writeFileSync(carrier, rawHex, { mode: 0o600 });
      try {
        const inspected = await engine.inspectShipGateArtifact(auth.tenant.id, carrier, "evm-bytecode", {
          label: "contract-bytecode.hex",
        });
        if (!inspected.ok) {
          billing.refundAlphaShieldQuota(auth.tenant.id, 1);
          const refreshed = billing.sanitizeTenant(billing.getTenantById(auth.tenant.id));
          sendJson(req, res, 422, { ...inspected, tenant: refreshed });
          return;
        }
        await kelviq.reportScanUsage(auth.tenant.id, "contract-scans");
        sendJson(req, res, 200, { ...inspected, tenant: quota.tenant });
      } catch (err) {
        billing.refundAlphaShieldQuota(auth.tenant.id, 1);
        throw err;
      } finally {
        rmSync(carrier, { force: true });
      }
      return;
    }

    if (req.method === "POST" && pathname === "/api/alphashield/apk-audit") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `apkaudit:${auth.tenant.id}`, req, res)) return;

      const contentType = String(req.headers["content-type"] || "");
      let filename = sanitizeFilename(req.headers["x-filename"] || "package.apk");
      let sampleBytes = null;
      let declaredSize = 0;
      let clientSha256 = "";

      if (contentType.includes("application/json")) {
        const body = await readJsonBody(req, 8 * 1024 * 1024);
        filename = sanitizeFilename(body.filename || filename);
        declaredSize = Math.max(0, Number(body.size_bytes || 0));
        clientSha256 = String(body.sha256 || "").trim().toLowerCase();
        if (body.sample_base64) {
          sampleBytes = Buffer.from(String(body.sample_base64), "base64");
        }
      } else {
        sampleBytes = await readBodyBuffer(req, MAX_UPLOAD_BYTES);
        declaredSize = sampleBytes.length;
      }

      if (!sampleBytes || sampleBytes.length === 0) {
        sendJson(req, res, 400, { ok: false, error: { message: "Provide a non-empty APK or binary sample." } });
        return;
      }
      if (sampleBytes.length > MAX_UPLOAD_BYTES) {
        throw new PayloadTooLargeError(MAX_UPLOAD_BYTES);
      }

      const tenantScratch = join(engine.uploadsDir, auth.tenant.id);
      ensurePrivateDir(tenantScratch);
      const apkScratchSlot = join(tenantScratch, `apk-${randomUUID()}`);
      const apkReservation = reserveTenantStorage(auth.tenant.id, sampleBytes.length, {
        excludeDir: apkScratchSlot,
        maxBytes: MAX_TENANT_UPLOAD_BYTES,
      });

      let quotaConsumed = false;
      let cleanedApkScratch = false;
      const cleanupApkScratch = () => {
        if (cleanedApkScratch) return;
        cleanedApkScratch = true;
        try {
          rmSync(apkScratchSlot, { recursive: true, force: true });
        } finally {
          apkReservation.release();
        }
      };

      try {
        const quota = billing.checkAndConsumeAlphaShieldQuota(auth.tenant);
        if (!quota.ok) {
          cleanupApkScratch();
          sendJson(req, res, quota.status || 402, quota);
          return;
        }
        quotaConsumed = true;

        ensurePrivateDir(apkScratchSlot);
        const carrier = join(apkScratchSlot, filename);
        writeFileSync(carrier, sampleBytes, { mode: 0o600 });

        const computedSha256 =
          /^[a-f0-9]{64}$/.test(clientSha256) && declaredSize > sampleBytes.length
            ? clientSha256
            : createHash("sha256").update(sampleBytes).digest("hex");

        let reaInspection = null;
        if (declaredSize <= sampleBytes.length) {
          reaInspection = await engine.inspectShipGateArtifact(auth.tenant.id, carrier, "auto", {
            label: filename,
          });
        }

        // Release scratch file and storage reservation immediately once binary inspection completes
        cleanupApkScratch();

        const asciiWindow = sampleBytes.toString("latin1");
        const isZipOrApk = sampleBytes[0] === 0x50 && sampleBytes[1] === 0x4b;
        const isElf =
          sampleBytes[0] === 0x7f &&
          sampleBytes[1] === 0x45 &&
          sampleBytes[2] === 0x4c &&
          sampleBytes[3] === 0x46;
        const isPe = sampleBytes[0] === 0x4d && sampleBytes[1] === 0x5a;

        const indicators = {
          accessibility_service: /BIND_ACCESSIBILITY_SERVICE|AccessibilityService/i.test(asciiWindow),
          sms_intercept: /RECEIVE_SMS|READ_SMS/i.test(asciiWindow),
          overlay_window: /SYSTEM_ALERT_WINDOW/i.test(asciiWindow),
          seed_phrase_prompt:
            /mnemonic|seed.?phrase|12.?word|24.?word|recovery.?phrase|private.?key/i.test(asciiWindow) &&
            /api\.telegram\.org|discord\.com\/api\/webhooks|fetch\(|okhttp/i.test(asciiWindow),
          dynamic_dex_load: /DexClassLoader|InMemoryDexClassLoader/i.test(asciiWindow),
          apk_signing_block: /APK Sig Block 42/.test(asciiWindow),
        };

        await kelviq.reportScanUsage(auth.tenant.id, "apk-scans");
        sendJson(req, res, 200, {
          ok: true,
          artifact: {
            filename,
            size_bytes: declaredSize || sampleBytes.length,
            sha256: computedSha256,
            format: isZipOrApk ? "APK / ZIP" : isElf ? "ELF Binary" : isPe ? "Windows PE" : "Binary",
          },
          indicators,
          rea: reaInspection?.ok ? reaInspection : null,
          tenant: quota.tenant,
        });
      } catch (err) {
        if (quotaConsumed) {
          billing.refundAlphaShieldQuota(auth.tenant.id, 1);
        }
        throw err;
      } finally {
        cleanupApkScratch();
      }
      return;
    }

    // -----------------------------------------------------------------------
    // Authenticated Tenant-Scoped File Upload Endpoint
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/upload") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `upload:${auth.tenant.id}:${clientIp}`, req, res)) return;

      const contentType = req.headers["content-type"] || "";
      let filename = sanitizeFilename(req.headers["x-filename"] || "uploaded.bin");
      let fileBuffer;

      if (contentType.includes("application/json")) {
        const body = await readJsonBody(req, MAX_UPLOAD_BYTES);
        filename = sanitizeFilename(body.filename || filename);
        fileBuffer = Buffer.from(String(body.base64 || ""), "base64");
      } else {
        fileBuffer = await readBodyBuffer(req, MAX_UPLOAD_BYTES);
      }

      const saved = saveTenantUpload(auth.tenant.id, filename, fileBuffer);
      sendJson(req, res, 200, { ok: true, ...saved });
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 1: Electron / JavaScript X-Ray Routes (Pre-Quota Checked + Temp Cleanup)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/xray/scan") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `scan:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req);
      let sampleTarget = null;
      let uploadCandidate = null;
      let label;

      if (body.sample_id) {
        sampleTarget = samples.electronTargets.find((t) => t.id === body.sample_id);
        if (!sampleTarget) {
          sendJson(req, res, 404, { ok: false, error: { message: "Unknown sample_id" } });
          return;
        }
        label = sampleTarget.name;
      } else if (body.saved_path) {
        uploadCandidate = resolveTenantUploadPath(auth.tenant.id, body.saved_path);
        label = basename(uploadCandidate);
      } else {
        sendJson(req, res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
        return;
      }

      // Check and consume quota BEFORE unpacking any archive
      const quota = billing.checkAndConsumeQuota(auth.tenant, "scan", 1);
      if (!quota.ok) {
        sendJson(req, res, quota.status || 402, quota);
        return;
      }

      let prepared = null;
      try {
        const targetPath = sampleTarget
          ? sampleTarget.path
          : (prepared = await prepareUploadedXrayTarget(auth.tenant.id, uploadCandidate)).targetPath;
        const result = await engine.scanJavaScriptApplication(auth.tenant.id, targetPath, label);
        if (!result.ok) {
          billing.refundQuota(auth.tenant.id, "scan", 1);
          const refreshed = billing.sanitizeTenant(billing.getTenantById(auth.tenant.id));
          sendJson(req, res, result.status || 422, { ...result, tenant: refreshed });
          return;
        }
        sendJson(req, res, 200, { ...result, tenant: quota.tenant });
      } catch (err) {
        billing.refundQuota(auth.tenant.id, "scan", 1);
        throw err;
      } finally {
        prepared?.cleanup();
      }
      return;
    }

    if (req.method === "POST" && pathname === "/api/xray/trace") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `trace:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req);
      const result = await engine.traceJavaScriptFeature(
        auth.tenant.id,
        body.evidence_id,
        body.seed_kind || "channel",
        body.seed_value || "",
        body.direction || "both",
        body.match || "contains",
      );
      sendJson(req, res, result.ok ? 200 : result.status || 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/xray/compare") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `cmp:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req);
      const validateSideSpec = (val, defaultSampleId) => {
        const str = String(val ?? defaultSampleId).trim();
        if (!str) {
          throw new BadRequestError("Missing comparison target.", 400);
        }
        if (str.startsWith("ev_")) {
          if (!engine.getEvidenceRecord(auth.tenant.id, str)) {
            throw new BadRequestError("Referenced Evidence envelope not found in active workspace.", 404);
          }
          return { kind: "evidence", ref: str, consumesScan: false };
        }
        if (str.startsWith("upload://")) {
          const uploaded = resolveTenantUploadPath(auth.tenant.id, str);
          return { kind: "upload", candidate: uploaded, consumesScan: true };
        }
        const sample = samples.electronTargets.find((t) => t.id === str);
        if (!sample) {
          throw new BadRequestError(`Unknown comparison target: ${str}`, 404);
        }
        return { kind: "sample", ref: sample.path, consumesScan: true };
      };

      const leftSpec = validateSideSpec(body.left, "acme-desktop-v1");
      const rightSpec = validateSideSpec(body.right, "acme-desktop-v2");
      const scanUnits = (leftSpec.consumesScan ? 1 : 0) + (rightSpec.consumesScan ? 1 : 0);

      let updatedTenant = billing.sanitizeTenant(auth.tenant);
      if (scanUnits > 0) {
        const quota = billing.checkAndConsumeQuota(auth.tenant, "scan", scanUnits);
        if (!quota.ok) {
          sendJson(req, res, quota.status || 402, quota);
          return;
        }
        updatedTenant = quota.tenant;
      }

      const cleanups = [];
      try {
        const materializeSide = async (spec) => {
          if (spec.kind !== "upload") return spec.ref;
          const prep = await prepareUploadedXrayTarget(auth.tenant.id, spec.candidate);
          cleanups.push(prep.cleanup);
          return prep.targetPath;
        };
        const leftRef = await materializeSide(leftSpec);
        const rightRef = await materializeSide(rightSpec);
        const result = await engine.compareJavaScriptVersions(auth.tenant.id, leftRef, rightRef);
        if (!result.ok) {
          if (scanUnits > 0) {
            billing.refundQuota(auth.tenant.id, "scan", scanUnits);
            updatedTenant = billing.sanitizeTenant(billing.getTenantById(auth.tenant.id));
          }
          sendJson(req, res, result.status || 422, { ...result, tenant: updatedTenant });
          return;
        }
        sendJson(req, res, 200, {
          ...result,
          tenant: updatedTenant,
        });
      } catch (err) {
        if (scanUnits > 0) {
          billing.refundQuota(auth.tenant.id, "scan", scanUnits);
        }
        throw err;
      } finally {
        for (const fn of cleanups) {
          try {
            fn();
          } catch {
            // ignore cleanup errors
          }
        }
      }
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 2: ShipGate Binary / Model / EVM / Bytecode Gate Routes (Metered)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/shipgate/inspect") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `sg:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req);
      let targetPath;
      let category = body.category || "auto";
      let label;

      if (body.sample_id) {
        const found = samples.binaryTargets.find((t) => t.id === body.sample_id);
        if (!found) {
          sendJson(req, res, 404, { ok: false, error: { message: "Unknown binary sample_id" } });
          return;
        }
        targetPath = found.path;
        label = basename(found.path);
        if (category === "auto") category = found.category;
      } else if (body.saved_path) {
        targetPath = resolveTenantUploadPath(auth.tenant.id, body.saved_path);
        label = basename(targetPath);
      } else {
        sendJson(req, res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
        return;
      }

      const quota = billing.checkAndConsumeQuota(auth.tenant, "scan", 1);
      if (!quota.ok) {
        sendJson(req, res, quota.status || 402, quota);
        return;
      }

      try {
        const result = await engine.inspectShipGateArtifact(auth.tenant.id, targetPath, category, {
          symbol: body.symbol || undefined,
          label,
        });
        if (!result.ok) {
          billing.refundQuota(auth.tenant.id, "scan", 1);
          const refreshed = billing.sanitizeTenant(billing.getTenantById(auth.tenant.id));
          sendJson(req, res, result.status || 422, { ...result, tenant: refreshed });
          return;
        }
        sendJson(req, res, 200, { ...result, tenant: quota.tenant });
      } catch (err) {
        billing.refundQuota(auth.tenant.id, "scan", 1);
        throw err;
      }
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 3: HAR-to-RL AgentEnv Factory Routes (Browser Session & Tenant-Scoped)
    // -----------------------------------------------------------------------
    if (req.method === "POST" && pathname === "/api/rl/build") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `rlbuild:${auth.tenant.id}`, req, res)) return;

      const body = await readJsonBody(req);
      let harPath;
      let envName = body.name || "agent-env";

      if (body.sample_id) {
        const found = samples.harTargets.find((t) => t.id === body.sample_id);
        if (!found) {
          sendJson(req, res, 404, { ok: false, error: { message: "Unknown HAR sample_id" } });
          return;
        }
        harPath = found.path;
        envName = body.name || found.envName;
      } else if (body.saved_path) {
        harPath = resolveTenantUploadPath(auth.tenant.id, body.saved_path);
        envName = body.name || basename(harPath, extname(harPath));
      } else {
        sendJson(req, res, 400, { ok: false, error: { message: "Provide sample_id or saved_path" } });
        return;
      }

      const quota = billing.checkAndConsumeQuota(auth.tenant, "rl_build", 1);
      if (!quota.ok) {
        sendJson(req, res, quota.status || 402, quota);
        return;
      }

      try {
        const result = await engine.buildAndServeAgentEnvironment(auth.tenant.id, harPath, envName);
        if (!result.ok) {
          billing.refundQuota(auth.tenant.id, "rl_build", 1);
          const refreshed = billing.sanitizeTenant(billing.getTenantById(auth.tenant.id));
          sendJson(req, res, result.status || 422, { ...result, tenant: refreshed });
          return;
        }
        sendJson(req, res, 200, { ...result, tenant: quota.tenant });
      } catch (err) {
        billing.refundQuota(auth.tenant.id, "rl_build", 1);
        throw err;
      }
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/call") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `rlcall:${auth.tenant.id}`, req, res)) return;
      const body = await readJsonBody(req);
      const result = await engine.callLiveAgentTool(
        auth.tenant.id,
        body.env_id,
        body.tool,
        body.arguments || {},
      );
      sendJson(req, res, result.ok ? 200 : result.status || 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/reset") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `rlreset:${auth.tenant.id}`, req, res)) return;
      const body = await readJsonBody(req);
      const result = await engine.resetLiveAgentState(auth.tenant.id, body.env_id);
      sendJson(req, res, result.ok ? 200 : result.status || 422, result);
      return;
    }

    if (req.method === "POST" && pathname === "/api/rl/grade-task") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      if (!enforceRateLimit(apiLimiter, `rlgrade:${auth.tenant.id}`, req, res)) return;
      const body = await readJsonBody(req);
      const result = await engine.evaluateAndSaveRlTask(auth.tenant.id, body.env_id, body.task || {});
      sendJson(req, res, result.ok ? 200 : result.status || 422, result);
      return;
    }

    if (req.method === "GET" && pathname.startsWith("/api/rl/download/")) {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      const envId = decodeRlDownloadEnvId(pathname.slice("/api/rl/download/".length));
      const env = engine.getAuthorizedEnvironment(auth.tenant.id, envId);
      if (!env) {
        sendJson(req, res, 404, {
          ok: false,
          error: { message: "Environment bundle not found in active workspace" },
        });
        return;
      }

      const zipBuf = zipDirectory(env.bundle_dir, env.name);
      res.writeHead(
        200,
        buildSecurityHeaders(req, {
          "content-type": "application/zip",
          "content-length": zipBuf.length,
          "content-disposition": `attachment; filename="${env.name}-agentenv.zip"`,
          "cache-control": "no-store",
        }),
      );
      res.end(zipBuf);
      return;
    }

    // -----------------------------------------------------------------------
    // TAB 4: Tenant-Scoped Evidence Ledger & API Key Management
    // -----------------------------------------------------------------------
    if (req.method === "GET" && pathname === "/api/evidence") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      sendJson(req, res, 200, {
        ok: true,
        tenant: billing.sanitizeTenant(auth.tenant),
        records: engine.listEvidence(auth.tenant.id),
      });
      return;
    }

    const reportMatch = pathname.match(/^\/api\/evidence\/(ev_[a-f0-9]{64})\/report$/);
    if (req.method === "GET" && reportMatch) {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      const record = engine.getEvidenceRecord(auth.tenant.id, reportMatch[1]);
      if (!record) {
        sendJson(req, res, 404, { ok: false, error: { message: "Evidence not found in active workspace" } });
        return;
      }
      const format = url.searchParams.get("format") || "md";
      if (format === "json") {
        const exportedEvidence = engine.exportSchemaValidEvidence(record);
        const jsonBytes = Buffer.from(JSON.stringify(exportedEvidence, null, 2), "utf8");
        res.writeHead(
          200,
          buildSecurityHeaders(req, {
            "content-type": "application/json; charset=utf-8",
            "content-length": jsonBytes.length,
            "content-disposition": `attachment; filename="${record.evidence_id.slice(0, 16)}.evidence.json"`,
            "cache-control": "no-store",
          }),
        );
        res.end(jsonBytes);
      } else {
        const md = renderAuditMarkdown(record, record.posture ?? null);
        const mdBytes = Buffer.from(md, "utf8");
        res.writeHead(
          200,
          buildSecurityHeaders(req, {
            "content-type": "text/markdown; charset=utf-8",
            "content-length": mdBytes.length,
            "content-disposition": `attachment; filename="${record.evidence_id.slice(0, 16)}-audit.md"`,
            "cache-control": "no-store",
          }),
        );
        res.end(mdBytes);
      }
      return;
    }

    const detailMatch = pathname.match(/^\/api\/evidence\/(ev_[a-f0-9]{64})$/);
    if (req.method === "GET" && detailMatch) {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      const record = engine.getEvidenceRecord(auth.tenant.id, detailMatch[1]);
      if (!record) {
        sendJson(req, res, 404, { ok: false, error: { message: "Evidence not found in active workspace" } });
        return;
      }
      const { tenant_id: _tid, ...safeRecord } = record;
      sendJson(req, res, 200, { ok: true, record: safeRecord });
      return;
    }

    if (req.method === "POST" && pathname === "/api/keys/create") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      const body = await readJsonBody(req, 64 * 1024);
      const out = billing.createApiKey(auth.tenant.id, body.name);
      sendJson(req, res, out.ok ? 200 : out.status || 400, out);
      return;
    }

    if (req.method === "POST" && pathname === "/api/keys/revoke") {
      const auth = requireBrowserSessionAuth(req, res);
      if (!auth) return;
      const body = await readJsonBody(req, 64 * 1024);
      const out = billing.revokeApiKey(auth.tenant.id, body.key_id);
      sendJson(req, res, out.ok ? 200 : 404, out);
      return;
    }

    // -----------------------------------------------------------------------
    // Authenticated, Rate-Limited & Quota-Metered B2B SaaS REST API v1
    // -----------------------------------------------------------------------
    if (pathname.startsWith("/api/v1/")) {
      if (!enforceRateLimit(apiLimiter, `v1:ip:${clientIp}`, req, res)) return;
      const authCtx = billing.authenticateApiKey(req);
      if (!authCtx) {
        sendJson(req, res, 401, {
          ok: false,
          error: {
            code: "unauthorized",
            message: "Missing or invalid Bearer API key. Generate a key in the Evidence & API Billing tab.",
          },
        });
        return;
      }
      const { keyRec, tenant } = authCtx;
      if (!enforceRateLimit(apiLimiter, `v1:tenant:${tenant.id}`, req, res)) return;
      engine.metrics.api_requests += 1;

      if (req.method === "GET" && pathname === "/api/v1/status") {
        sendJson(req, res, 200, {
          ok: true,
          authenticated_as: keyRec.name,
          organization: tenant.org_name,
          tenant: billing.sanitizeTenant(tenant),
          key_calls: keyRec.calls,
          rea_mcp_tools: engine.toolCount,
        });
        return;
      }

      if (req.method === "POST" && pathname === "/api/v1/upload") {
        const contentType = req.headers["content-type"] || "";
        let filename = sanitizeFilename(req.headers["x-filename"] || "uploaded.bin");
        let fileBuffer;
        if (contentType.includes("application/json")) {
          const body = await readJsonBody(req, MAX_UPLOAD_BYTES);
          filename = sanitizeFilename(body.filename || filename);
          fileBuffer = Buffer.from(String(body.base64 || ""), "base64");
        } else {
          fileBuffer = await readBodyBuffer(req, MAX_UPLOAD_BYTES);
        }
        const saved = saveTenantUpload(tenant.id, filename, fileBuffer);
        sendJson(req, res, 200, {
          ok: true,
          ...saved,
          billed_to: tenant.org_name,
        });
        return;
      }

      if (req.method === "POST" && pathname === "/api/v1/xray") {
        const body = await readJsonBody(req);
        let sampleTarget = null;
        let uploadCandidate = null;
        let label;
        if (body.saved_path) {
          uploadCandidate = resolveTenantUploadPath(tenant.id, body.saved_path);
          label = body.label ? sanitizeFilename(body.label) : basename(uploadCandidate);
        } else {
          sampleTarget = samples.electronTargets.find(
            (t) => t.id === (body.target || "acme-desktop-v1"),
          );
          if (!sampleTarget) {
            sendJson(req, res, 404, { ok: false, error: { message: "Unknown target" } });
            return;
          }
          label = sampleTarget.name;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "scan", 1);
        if (!quota.ok) {
          sendJson(req, res, quota.status || 402, quota);
          return;
        }

        let prepared = null;
        try {
          const targetPath = sampleTarget
            ? sampleTarget.path
            : (prepared = await prepareUploadedXrayTarget(tenant.id, uploadCandidate)).targetPath;
          const result = await engine.scanJavaScriptApplication(tenant.id, targetPath, label);
          if (!result.ok) {
            billing.refundQuota(tenant.id, "scan", 1);
            const refreshed = billing.sanitizeTenant(billing.getTenantById(tenant.id));
            sendJson(req, res, result.status || 422, {
              ...result,
              billed_to: tenant.org_name,
              tenant: refreshed,
            });
            return;
          }
          const rec = engine.getEvidenceRecord(tenant.id, result.evidence_id);
          sendJson(req, res, 200, {
            ...result,
            ...(body.include_markdown && rec
              ? { audit_markdown: renderAuditMarkdown(rec, rec.posture ?? null) }
              : {}),
            billed_to: tenant.org_name,
            tenant: quota.tenant,
          });
        } catch (err) {
          billing.refundQuota(tenant.id, "scan", 1);
          throw err;
        } finally {
          prepared?.cleanup();
        }
        return;
      }

      if (req.method === "POST" && pathname === "/api/v1/shipgate") {
        const body = await readJsonBody(req);
        let targetPath;
        let category = body.category || "auto";
        let label;
        if (body.saved_path) {
          targetPath = resolveTenantUploadPath(tenant.id, body.saved_path);
          label = basename(targetPath);
        } else {
          const sample = samples.binaryTargets.find((t) => t.id === (body.target || "libvault-elf"));
          if (!sample) {
            sendJson(req, res, 404, { ok: false, error: { message: "Unknown target" } });
            return;
          }
          targetPath = sample.path;
          label = basename(sample.path);
          if (category === "auto") category = sample.category;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "scan", 1);
        if (!quota.ok) {
          sendJson(req, res, quota.status || 402, quota);
          return;
        }

        try {
          const result = await engine.inspectShipGateArtifact(tenant.id, targetPath, category, {
            symbol: body.symbol || undefined,
            label,
          });
          if (!result.ok) {
            billing.refundQuota(tenant.id, "scan", 1);
            const refreshed = billing.sanitizeTenant(billing.getTenantById(tenant.id));
            sendJson(req, res, result.status || 422, {
              ...result,
              billed_to: tenant.org_name,
              tenant: refreshed,
            });
            return;
          }
          sendJson(req, res, 200, {
            ...result,
            billed_to: tenant.org_name,
            tenant: quota.tenant,
          });
        } catch (err) {
          billing.refundQuota(tenant.id, "scan", 1);
          throw err;
        }
        return;
      }

      if (req.method === "POST" && pathname === "/api/v1/rl/build") {
        const body = await readJsonBody(req);
        let harPath;
        let envName = body.name || "agent-env";
        if (body.saved_path) {
          harPath = resolveTenantUploadPath(tenant.id, body.saved_path);
          envName = body.name || basename(harPath, extname(harPath));
        } else {
          const sample = samples.harTargets.find((t) => t.id === (body.target || "helpdesk-crm"));
          if (!sample) {
            sendJson(req, res, 404, { ok: false, error: { message: "Unknown HAR target" } });
            return;
          }
          harPath = sample.path;
          envName = body.name || sample.envName;
        }

        const quota = billing.checkAndConsumeQuota(tenant, "rl_build", 1);
        if (!quota.ok) {
          sendJson(req, res, quota.status || 402, quota);
          return;
        }

        try {
          const result = await engine.buildAndServeAgentEnvironment(tenant.id, harPath, envName);
          if (!result.ok) {
            billing.refundQuota(tenant.id, "rl_build", 1);
            const refreshed = billing.sanitizeTenant(billing.getTenantById(tenant.id));
            sendJson(req, res, result.status || 422, {
              ...result,
              download_path: null,
              billed_to: tenant.org_name,
              tenant: refreshed,
            });
            return;
          }
          sendJson(req, res, 200, {
            ...result,
            download_path: `/api/v1/rl/download/${encodeURIComponent(result.env_id)}`,
            billed_to: tenant.org_name,
            tenant: quota.tenant,
          });
        } catch (err) {
          billing.refundQuota(tenant.id, "rl_build", 1);
          throw err;
        }
        return;
      }

      if (req.method === "GET" && pathname.startsWith("/api/v1/rl/download/")) {
        const envId = decodeRlDownloadEnvId(pathname.slice("/api/v1/rl/download/".length));
        const env = engine.getAuthorizedEnvironment(tenant.id, envId);
        if (!env) {
          sendJson(req, res, 404, {
            ok: false,
            error: { message: "Environment bundle not found in active workspace" },
          });
          return;
        }
        const zipBuf = zipDirectory(env.bundle_dir, env.name);
        res.writeHead(
          200,
          buildSecurityHeaders(req, {
            "content-type": "application/zip",
            "content-length": zipBuf.length,
            "content-disposition": `attachment; filename="${env.name}-agentenv.zip"`,
            "cache-control": "no-store",
          }),
        );
        res.end(zipBuf);
        return;
      }

      sendJson(req, res, 404, { ok: false, error: { message: "Unknown v1 endpoint" } });
      return;
    }

    if (pathname.startsWith("/api/")) {
      sendJson(req, res, 404, { ok: false, error: { message: "Unknown API endpoint" } });
      return;
    }

    // -----------------------------------------------------------------------
    // Static Frontend Serving (/alphashield + Studio SPA)
    // -----------------------------------------------------------------------
    if (pathname === "/alphashield" || pathname === "/alphashield/") {
      const alphaHtml = readFileSync(join(ALPHASHIELD_DIR, "index.html"));
      res.writeHead(
        200,
        buildSecurityHeaders(req, {
          "content-type": "text/html; charset=utf-8",
          "content-length": alphaHtml.length,
          "cache-control": "no-cache",
        }),
      );
      res.end(alphaHtml);
      return;
    }

    if (pathname === "/alphashield/app.js") {
      const alphaJs = readFileSync(join(ALPHASHIELD_DIR, "app.js"));
      res.writeHead(
        200,
        buildSecurityHeaders(req, {
          "content-type": "application/javascript; charset=utf-8",
          "content-length": alphaJs.length,
          "cache-control": "no-cache",
        }),
      );
      res.end(alphaJs);
      return;
    }

    if (pathname.startsWith("/alphashield/")) {
      const notFoundBody = Buffer.from("Not Found", "utf8");
      res.writeHead(
        404,
        buildSecurityHeaders(req, {
          "content-type": "text/plain; charset=utf-8",
          "content-length": notFoundBody.length,
          "cache-control": "no-store",
        }),
      );
      res.end(notFoundBody);
      return;
    }

    const publicRoot = resolve(PUBLIC_DIR);
    let filePath =
      pathname === "/" ? join(publicRoot, "index.html") : resolve(publicRoot, `.${normalize(pathname)}`);
    const isSafeUnderPublic =
      (filePath === publicRoot || filePath.startsWith(publicRoot + sep)) &&
      existsSync(filePath) &&
      statSync(filePath).isFile();

    if (!isSafeUnderPublic) {
      // Return genuine 404 for missing static assets with file extensions instead of SPA HTML fallback
      if (extname(pathname) !== "") {
        const notFoundBody = Buffer.from("Not Found", "utf8");
        res.writeHead(
          404,
          buildSecurityHeaders(req, {
            "content-type": "text/plain; charset=utf-8",
            "content-length": notFoundBody.length,
            "cache-control": "no-store",
          }),
        );
        res.end(notFoundBody);
        return;
      }
      filePath = join(publicRoot, "index.html");
    }
    const ext = extname(filePath).toLowerCase();
    const content = readFileSync(filePath);
    res.writeHead(
      200,
      buildSecurityHeaders(req, {
        "content-type": MIME_TYPES[ext] || "application/octet-stream",
        "content-length": content.length,
        "cache-control": "no-cache",
      }),
    );
    res.end(content);
  } catch (err) {
    if (err instanceof PayloadTooLargeError || err instanceof BadRequestError) {
      sendJson(req, res, err.statusCode, {
        ok: false,
        error: {
          ...(err.code ? { code: err.code } : {}),
          message: err.message,
        },
      });
      return;
    }
    console.error("[REA Studio] Unhandled server error:", err instanceof Error ? err.message : "error");
    sendJson(req, res, 500, {
      ok: false,
      error: { message: "Internal server error." },
    });
  }
});

const isDirectEntrypoint =
  Boolean(process.argv[1]) && resolve(process.argv[1]) === resolve(import.meta.dirname, "index.mjs");

if (isDirectEntrypoint && process.env.REA_STUDIO_NO_AUTO_LISTEN !== "true") {
  const housekeepingTimer = setInterval(() => {
    void runHousekeeping().catch(() => {});
  }, 60_000);
  housekeepingTimer.unref();

  await engine.init();
  server.listen(PORT, HOST, () => {
    console.log(
      `REA Cloud Studio listening on http://${HOST}:${PORT} (REA v6.8.0 · ${engine.toolCount} MCP tools ready)`,
    );
  });

  const shutdown = async () => {
    clearInterval(housekeepingTimer);
    server.close();
    await engine.close();
    billing.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
