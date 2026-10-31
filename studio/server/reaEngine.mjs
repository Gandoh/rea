import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, extname, join, relative, resolve } from "node:path";

import {
  Client,
  InMemoryTransport,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";

import { enrichEvmFunctions, evaluateJavaScriptSecurityPosture } from "./riskScoring.mjs";

const NOOP_VALIDATOR = {
  getValidator: () => () => ({ valid: true }),
};

const MAX_ACTIVE_RL_ENVS_PER_TENANT = 3;
const DEFAULT_MAX_GLOBAL_RL_ENVS = Number(process.env.REA_MAX_GLOBAL_RL_ENVS || 24);
const DEFAULT_MAX_EVIDENCE_ENTRIES = Number(process.env.REA_MAX_EVIDENCE_LEDGER || 500);
const DEFAULT_MAX_EVIDENCE_PER_TENANT = Number(process.env.REA_MAX_EVIDENCE_PER_TENANT || 64);
const DEFAULT_MAX_JS_SCANS = Number(process.env.REA_MAX_JS_SCANS || 250);
const DEFAULT_RL_IDLE_TTL_MS = Number(process.env.REA_RL_IDLE_TTL_MS || 15 * 60 * 1000);
const DEFAULT_MAX_TENANT_SESSIONS = Number(process.env.REA_MAX_TENANT_SESSIONS || 12);
const DEFAULT_MAX_SESSION_CALLS = Number(process.env.REA_MAX_SESSION_CALLS || 24);
const DEFAULT_SESSION_IDLE_TTL_MS = Number(process.env.REA_SESSION_IDLE_TTL_MS || 10 * 60 * 1000);

function ensureSecureDirectory(dirPath) {
  mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dirPath, 0o700);
  } catch {
    // Best-effort on filesystems without POSIX permissions.
  }
}

function assertTenantId(tenantId) {
  if (!tenantId || typeof tenantId !== "string") {
    throw new Error("A valid authenticated tenantId is required for engine operations.");
  }
}

function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function setBoundedMap(map, key, value, maxEntries) {
  if (map.has(key)) {
    map.delete(key);
  }
  map.set(key, value);
  let evicted = 0;
  while (map.size > maxEntries) {
    const oldestKey = map.keys().next().value;
    if (oldestKey === undefined) break;
    map.delete(oldestKey);
    evicted += 1;
  }
  return evicted;
}

/**
 * Tenant-isolated bounded map: enforces BOTH a per-tenant entry ceiling AND
 * largest-tenant-first LRU eviction under global pressure so one noisy tenant
 * can never wipe out other tenants' sealed Evidence or JS scan records.
 */
function setTenantFairBoundedMap(map, tenantId, key, value, maxGlobalEntries, maxPerTenantEntries) {
  const existed = map.has(key);
  if (existed) {
    map.delete(key);
  }
  map.set(key, value);

  let evicted = 0;
  const tenantPrefix = `${tenantId}:`;

  if (Number.isFinite(maxPerTenantEntries) && maxPerTenantEntries > 0) {
    const tenantKeys = [];
    for (const k of map.keys()) {
      if (String(k).startsWith(tenantPrefix)) tenantKeys.push(k);
    }
    while (tenantKeys.length > maxPerTenantEntries) {
      const victim = tenantKeys.shift();
      if (victim !== undefined && map.delete(victim)) {
        evicted += 1;
      }
    }
  }

  while (map.size > maxGlobalEntries) {
    const countsByTenant = new Map();
    const oldestKeyByTenant = new Map();
    for (const k of map.keys()) {
      const idx = String(k).indexOf(":");
      const owner = idx > 0 ? String(k).slice(0, idx) : "__global__";
      countsByTenant.set(owner, (countsByTenant.get(owner) || 0) + 1);
      if (!oldestKeyByTenant.has(owner)) {
        oldestKeyByTenant.set(owner, k);
      }
    }

    let largestOwner = null;
    let largestCount = -1;
    for (const [owner, cnt] of countsByTenant.entries()) {
      if (cnt > largestCount) {
        largestCount = cnt;
        largestOwner = owner;
      }
    }

    const victimKey =
      (largestOwner ? oldestKeyByTenant.get(largestOwner) : undefined) ??
      map.keys().next().value;
    if (victimKey === undefined) break;
    if (map.delete(victimKey)) {
      evicted += 1;
    }
  }

  return evicted;
}

function getBoundedMap(map, key) {
  if (!map.has(key)) return undefined;
  const val = map.get(key);
  map.delete(key);
  map.set(key, val);
  return val;
}

/**
 * Redacts server filesystem paths, runtime directories, temp unpack folders, and tenant IDs
 * from strings and nested JSON structures while preserving filenames, relative archive paths,
 * hashes, and security findings.
 */
export function createPathScrubber({ repoRoot, runtimeDir, extraPaths = [], tenantId = null }) {
  const roots = [
    runtimeDir,
    repoRoot,
    tmpdir(),
    "/private/tmp",
    "/var/tmp",
    "/tmp",
  ]
    .concat(extraPaths)
    .filter((p) => typeof p === "string" && p.trim().length > 1)
    .map((p) => resolve(p).replace(/\/+$/u, ""))
    .sort((a, b) => b.length - a.length);

  const rootRegexes = roots.map(
    (root) => new RegExp(`${escapeRegExp(root)}(?:/[^\\s"':\\x00-\\x1f]+)*`, "g"),
  );

  // Generic host home/temp/windows user path catchers
  const genericHostPathRegex =
    /(?:\/home\/[^\s"':\x00-\x1f]+|\/Users\/[^\s"':\x00-\x1f]+|\/root\/[^\s"':\x00-\x1f]+|\/var\/folders\/[^\s"':\x00-\x1f]+|[A-Za-z]:\\Users\\[^\s"':\x00-\x1f]+)/g;

  const tenantToken = tenantId && String(tenantId).trim() ? String(tenantId).trim() : null;

  const collapseMatchedPath = (matchedPath) => {
    const clean = matchedPath.replace(/\\/g, "/").replace(/\/+$/u, "");
    const base = basename(clean);
    if (
      !base ||
      base === "samples" ||
      base === "uploads" ||
      base === "bundles" ||
      base.startsWith("unpacked-") ||
      base.startsWith("rea-") ||
      (tenantToken && base === tenantToken)
    ) {
      return "<artifact>";
    }
    if (tenantToken && base.includes(tenantToken)) {
      return base.split(tenantToken).join("workspace");
    }
    return base;
  };

  const scrubString = (input) => {
    let s = String(input);
    for (const rx of rootRegexes) {
      s = s.replace(rx, collapseMatchedPath);
    }
    s = s.replace(genericHostPathRegex, collapseMatchedPath);
    if (tenantToken && s.includes(`/${tenantToken}`)) {
      s = s.split(`/${tenantToken}`).join("/<workspace>");
    }
    return s;
  };

  const scrubValue = (val) => {
    if (typeof val === "string") return scrubString(val);
    if (Array.isArray(val)) return val.map(scrubValue);
    if (val && typeof val === "object") {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = scrubValue(v);
      }
      return out;
    }
    return val;
  };

  return { scrubString, scrubValue };
}

/**
 * Sanitizes a user-visible Evidence envelope prior to ledger storage, API export,
 * Markdown reporting, or standalone HTML preview generation.
 */
export function sanitizeEvidenceEnvelope(
  evidence,
  { repoRoot, runtimeDir, extraPaths = [], tenantId = null, keepSchemaLocalPath = false } = {},
) {
  if (!evidence || typeof evidence !== "object") return evidence;
  const { scrubString, scrubValue } = createPathScrubber({
    repoRoot,
    runtimeDir,
    extraPaths,
    tenantId,
  });

  const cloned = scrubValue(JSON.parse(JSON.stringify(evidence)));

  // Never expose caller_input_path or host execution environment metadata
  delete cloned.caller_input_path;
  cloned.environment = null;

  if (cloned.subject && typeof cloned.subject === "object") {
    const safeName =
      scrubString(cloned.subject.name || basename(String(evidence.subject?.local_path || "")) || "artifact")
        .replace(/^<artifact>$/, "artifact");
    cloned.subject.name = safeName;
    if (keepSchemaLocalPath) {
      cloned.subject.local_path = safeName;
    } else {
      delete cloned.subject.local_path;
    }
  }

  if (cloned.parameters && typeof cloned.parameters === "object") {
    for (const pathKey of ["path", "input_path", "capture_path"]) {
      if (typeof cloned.parameters[pathKey] === "string") {
        const rawOrig = String(evidence.parameters?.[pathKey] || cloned.parameters[pathKey]);
        const safeBase = basename(rawOrig.replace(/\\/g, "/")) || "artifact";
        cloned.parameters[pathKey] = safeBase.startsWith("unpacked-") ? "artifact" : safeBase;
      }
    }
    if ("output_directory" in cloned.parameters) {
      if (keepSchemaLocalPath) {
        cloned.parameters.output_directory = "bundle";
      } else {
        delete cloned.parameters.output_directory;
      }
    }
  }

  return cloned;
}

/**
 * Persistent in-process REA Engine Bridge + Tenant-Isolated Live AgentEnv Supervisor.
 */
export class ReaStudioEngine {
  constructor(repoRoot, runtimeDir, options = {}) {
    this.repoRoot = repoRoot;
    this.runtimeDir = runtimeDir;
    this.bundlesDir = join(runtimeDir, "bundles");
    this.uploadsDir = join(runtimeDir, "uploads");
    ensureSecureDirectory(this.runtimeDir);
    ensureSecureDirectory(this.bundlesDir);
    ensureSecureDirectory(this.uploadsDir);

    this.maxEvidenceEntries = Math.max(
      4,
      Number(options.maxEvidenceEntries || DEFAULT_MAX_EVIDENCE_ENTRIES),
    );
    this.maxEvidencePerTenant = Math.max(
      2,
      Math.min(
        this.maxEvidenceEntries,
        Number(options.maxEvidencePerTenant || DEFAULT_MAX_EVIDENCE_PER_TENANT),
      ),
    );
    this.maxJsScans = Math.max(4, Number(options.maxJsScans || DEFAULT_MAX_JS_SCANS));
    this.maxJsScansPerTenant = Math.max(
      2,
      Math.min(this.maxJsScans, Number(options.maxJsScansPerTenant || DEFAULT_MAX_EVIDENCE_PER_TENANT)),
    );
    this.rlIdleTtlMs = Math.max(1000, Number(options.rlIdleTtlMs || DEFAULT_RL_IDLE_TTL_MS));
    this.maxTenantLiveEnvs = Math.max(
      1,
      Number(options.maxTenantLiveEnvs || MAX_ACTIVE_RL_ENVS_PER_TENANT),
    );
    this.maxGlobalLiveEnvs = Math.max(
      1,
      Number(options.maxGlobalLiveEnvs || DEFAULT_MAX_GLOBAL_RL_ENVS),
    );
    this.maxTenantSessions = Math.max(
      2,
      Number(options.maxTenantSessions || DEFAULT_MAX_TENANT_SESSIONS),
    );
    this.maxCallsPerTenantSession = Math.max(
      2,
      Number(options.maxCallsPerTenantSession || DEFAULT_MAX_SESSION_CALLS),
    );
    this.sessionIdleTtlMs = Math.max(
      1000,
      Number(options.sessionIdleTtlMs || DEFAULT_SESSION_IDLE_TTL_MS),
    );

    this.initialized = false;
    this.distMod = null;
    this.parsedConfig = null;
    this.toolCount = 0;

    /** @type {Map<string, object>} per-tenant bounded & auto-rotating MCP BinarySession pool */
    this.tenantSessions = new Map();
    /** @type {Map<string, object>} bounded LRU keyed by `${tenantId}:${evidenceId}` */
    this.evidenceLedger = new Map();
    /** @type {Map<string, string>} bounded alias map `${tenantId}:${originalEvidenceId}` -> `redactedEvidenceId` */
    this.evidenceIdAliases = new Map();
    /** @type {Map<string, object>} bounded LRU keyed by `${tenantId}:${evidenceId}` */
    this.jsScansByTarget = new Map();
    /** @type {Map<string, object>} keyed by `envId` with mandatory `tenant_id` */
    this.liveEnvironments = new Map();

    this.metrics = {
      scans_completed: 0,
      evidence_sealed: 0,
      evidence_evicted: 0,
      mcp_sessions_recycled: 0,
      rl_bundles_built: 0,
      rl_tool_calls: 0,
      rl_idle_reaped: 0,
      api_requests: 0,
      started_at: new Date().toISOString(),
    };
  }

  async init() {
    if (this.initialized) return;
    const distRoot = resolve(this.repoRoot, "dist");
    if (!existsSync(join(distRoot, "server/createServer.js"))) {
      throw new Error(
        `REA compiled dist/ not found at ${distRoot}. Run npm ci && npm run build:cached first.`,
      );
    }

    const [
      { createBinarySession },
      { parseConfig },
      { silentLogger },
      { createServer },
      { loadEnvironmentSource },
      { prepareServedState },
      { serveEnvironment },
      { evidenceSemanticContent, parseEvidence },
      { digestCanonicalValue },
    ] = await Promise.all([
      import(join(distRoot, "composition/binary.js")),
      import(join(distRoot, "config/parseConfig.js")),
      import(join(distRoot, "logger.js")),
      import(join(distRoot, "server/createServer.js")),
      import(join(distRoot, "application/environment/environmentSource.js")),
      import(join(distRoot, "application/environment/environmentState.js")),
      import(join(distRoot, "server/environment/serveEnvironment.js")),
      import(join(distRoot, "domain/evidence.js")),
      import(join(distRoot, "domain/canonicalDigest.js")),
    ]);

    const configured = parseConfig({ REA_ANALYSIS_PROVIDER: "auto" });
    if (!configured.ok) throw configured.error;

    this.parsedConfig = configured.value;
    this.distMod = {
      createBinarySession,
      createServer,
      silentLogger,
      loadEnvironmentSource,
      prepareServedState,
      serveEnvironment,
      evidenceSemanticContent,
      parseEvidence,
      digestCanonicalValue,
    };

    // Probe catalog tool count once using a short-lived bootstrap session, then close immediately.
    const probeSlot = await this.createIsolatedMcpSlot("__catalog_probe__");
    try {
      const catalog = await probeSlot.client.listTools();
      this.toolCount = catalog.tools.length;
    } finally {
      await this.destroyMcpSlot(probeSlot);
    }
    this.initialized = true;
  }

  async createIsolatedMcpSlot(tenantId) {
    const session = this.distMod.createBinarySession(
      this.parsedConfig,
      this.distMod.silentLogger,
      process.env,
    );
    const server = this.distMod.createServer({ kind: "session", session });
    const client = new Client(
      { name: "rea-cloud-studio", version: "1.0.0" },
      { jsonSchemaValidator: NOOP_VALIDATOR },
    );
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    return {
      tenantId,
      session,
      server,
      client,
      calls: 0,
      pins: 0,
      closed: false,
      lastActiveAt: Date.now(),
    };
  }

  async destroyMcpSlot(slot) {
    if (!slot || slot.closed) return;
    slot.closed = true;
    if (this.tenantSessions.get(slot.tenantId) === slot) {
      this.tenantSessions.delete(slot.tenantId);
    }
    try {
      await slot.client.close();
    } catch {
      // ignore close errors
    }
    try {
      await slot.server.close();
    } catch {
      // ignore close errors
    }
    try {
      await slot.session.close();
    } catch {
      // ignore close errors
    }
  }

  async reapIdleTenantSessions(maxIdleMs = this.sessionIdleTtlMs) {
    const now = Date.now();
    let reaped = 0;
    for (const slot of [...this.tenantSessions.values()]) {
      if (slot.pins === 0 && now - Number(slot.lastActiveAt || 0) >= maxIdleMs) {
        await this.destroyMcpSlot(slot);
        this.metrics.mcp_sessions_recycled += 1;
        reaped += 1;
      }
    }
    return reaped;
  }

  async acquireTenantSessionSlot(tenantId) {
    assertTenantId(tenantId);
    await this.init();
    await this.reapIdleTenantSessions();

    let slot = this.tenantSessions.get(tenantId);
    if (slot && slot.pins === 0 && slot.calls >= this.maxCallsPerTenantSession) {
      await this.destroyMcpSlot(slot);
      this.metrics.mcp_sessions_recycled += 1;
      slot = null;
    }

    if (!slot) {
      while (this.tenantSessions.size >= this.maxTenantSessions) {
        const evictable = [...this.tenantSessions.values()].find((s) => s.pins === 0);
        if (!evictable) break;
        await this.destroyMcpSlot(evictable);
        this.metrics.mcp_sessions_recycled += 1;
      }
      slot = await this.createIsolatedMcpSlot(tenantId);
      this.tenantSessions.set(tenantId, slot);
    } else {
      // Refresh LRU position
      this.tenantSessions.delete(tenantId);
      this.tenantSessions.set(tenantId, slot);
    }

    slot.pins += 1;
    slot.lastActiveAt = Date.now();
    return slot;
  }

  async releaseTenantSessionSlot(slot) {
    if (!slot) return;
    slot.pins = Math.max(0, slot.pins - 1);
    slot.lastActiveAt = Date.now();
    if (slot.pins === 0 && slot.calls >= this.maxCallsPerTenantSession) {
      await this.destroyMcpSlot(slot);
      this.metrics.mcp_sessions_recycled += 1;
    }
  }

  async withPinnedTenantSession(tenantId, fn) {
    const slot = await this.acquireTenantSessionSlot(tenantId);
    try {
      return await fn(slot);
    } finally {
      await this.releaseTenantSessionSlot(slot);
    }
  }

  ledgerKey(tenantId, evidenceId) {
    assertTenantId(tenantId);
    return `${tenantId}:${evidenceId}`;
  }

  computeAuthenticatedEvidenceId(evidenceWithoutOrWithId) {
    const semantic = this.distMod.evidenceSemanticContent(evidenceWithoutOrWithId);
    return `ev_${this.distMod.digestCanonicalValue(semantic, "Evidence")}`;
  }

  sanitizeForTenant(tenantId, evidence, extraPaths = []) {
    return sanitizeEvidenceEnvelope(evidence, {
      repoRoot: this.repoRoot,
      runtimeDir: this.runtimeDir,
      extraPaths,
      tenantId,
      keepSchemaLocalPath: false,
    });
  }

  remapTenantEvidenceReferences(tenantId, evidence) {
    if (Array.isArray(evidence.evidence_links)) {
      evidence.evidence_links = evidence.evidence_links.map((link) => {
        if (!link || typeof link !== "object" || typeof link.evidence_id !== "string") return link;
        const mapped = this.evidenceIdAliases.get(this.ledgerKey(tenantId, link.evidence_id));
        return mapped ? { ...link, evidence_id: mapped } : link;
      });
    }
    if (
      evidence.normalized_result &&
      typeof evidence.normalized_result === "object" &&
      typeof evidence.normalized_result.parent_evidence_id === "string"
    ) {
      const mappedParent = this.evidenceIdAliases.get(
        this.ledgerKey(tenantId, evidence.normalized_result.parent_evidence_id),
      );
      if (mappedParent) {
        evidence.normalized_result.parent_evidence_id = mappedParent;
      }
    }
  }

  sealRedactedEvidence(evidence, originalEvidenceId) {
    const preDigest = this.computeAuthenticatedEvidenceId(evidence);
    const isRedacted = preDigest !== originalEvidenceId;
    if (isRedacted) {
      const provenanceNote =
        `Studio multi-tenant redacted export: host paths and runtime environment metadata were sanitized; ` +
        `evidence_id commits to this redacted payload (original sealed evidence_id: ${originalEvidenceId}).`;
      const existingLimitations = Array.isArray(evidence.limitations) ? [...evidence.limitations] : [];
      if (!existingLimitations.includes(provenanceNote)) {
        existingLimitations.push(provenanceNote);
      }
      evidence.limitations = existingLimitations;
      evidence.evidence_id = this.computeAuthenticatedEvidenceId(evidence);
    } else {
      evidence.evidence_id = preDigest;
    }
    return { isRedacted, evidenceId: evidence.evidence_id };
  }

  /**
   * Produces a standalone `.evidence.json` / inline-MCP-compatible Evidence envelope
   * with `subject.local_path` populated to the safe redacted artifact basename.
   * Note: `evidenceSubjectIdentity` excludes `subject.local_path` and `subject.name`,
   * so `evidence_id` remains cryptographically identical and passes `parseEvidence()`.
   */
  exportSchemaValidEvidence(entryOrEvidence) {
    const src = entryOrEvidence?.evidence ? entryOrEvidence.evidence : entryOrEvidence;
    if (!src || typeof src !== "object") return null;
    const cloned = structuredClone(src);
    if (cloned.subject && typeof cloned.subject === "object") {
      cloned.subject = {
        ...cloned.subject,
        local_path: String(cloned.subject.name || "artifact"),
      };
    }
    return cloned;
  }

  recordEvidence(tenantId, rawEvidence, label, category, extraPaths = []) {
    assertTenantId(tenantId);
    if (!rawEvidence || typeof rawEvidence.evidence_id !== "string") return null;

    const originalEvidenceId = rawEvidence.evidence_id;
    const evidence = this.sanitizeForTenant(tenantId, rawEvidence, extraPaths);
    if (label && evidence.subject && (evidence.subject.name === "samples" || evidence.subject.name === "artifact")) {
      evidence.subject.name = String(label);
    }
    this.remapTenantEvidenceReferences(tenantId, evidence);
    const { isRedacted } = this.sealRedactedEvidence(evidence, originalEvidenceId);

    const key = this.ledgerKey(tenantId, evidence.evidence_id);
    setBoundedMap(
      this.evidenceIdAliases,
      this.ledgerKey(tenantId, originalEvidenceId),
      evidence.evidence_id,
      this.maxEvidenceEntries * 2,
    );

    const entry = {
      tenant_id: tenantId,
      evidence_id: evidence.evidence_id,
      original_evidence_id: originalEvidenceId,
      is_redacted: isRedacted,
      label: label || evidence.subject?.name || evidence.operation,
      category,
      operation: evidence.operation,
      subject_name: evidence.subject?.name ?? null,
      subject_sha256: evidence.subject?.digest?.sha256 ?? null,
      format: evidence.subject?.format ?? null,
      provider: evidence.provider ?? null,
      authority: evidence.authority ?? "unknown",
      confidence: evidence.confidence ?? "unknown",
      limitations_count: Array.isArray(evidence.limitations) ? evidence.limitations.length : 0,
      created_at: new Date().toISOString(),
      evidence,
    };
    const existed = this.evidenceLedger.has(key);
    const evictedCount = setTenantFairBoundedMap(
      this.evidenceLedger,
      tenantId,
      key,
      entry,
      this.maxEvidenceEntries,
      this.maxEvidencePerTenant,
    );
    if (!existed) {
      this.metrics.evidence_sealed += 1;
    }
    if (evictedCount > 0) {
      this.metrics.evidence_evicted += evictedCount;
    }
    return entry;
  }

  async callMcpTool(tenantId, name, args, label = null, category = "analysis", extraPaths = []) {
    assertTenantId(tenantId);
    const slot = await this.acquireTenantSessionSlot(tenantId);
    let res;
    const t0 = Date.now();
    try {
      slot.calls += 1;
      res = await slot.client.callTool({ name, arguments: args });
    } finally {
      await this.releaseTenantSessionSlot(slot);
    }
    const elapsedMs = Date.now() - t0;

    const { scrubValue } = createPathScrubber({
      repoRoot: this.repoRoot,
      runtimeDir: this.runtimeDir,
      extraPaths,
      tenantId,
    });

    if (res.isError) {
      const text = res.content?.find((c) => c.type === "text")?.text ?? "MCP tool failed";
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { message: text };
      }
      return {
        ok: false,
        elapsed_ms: elapsedMs,
        error: scrubValue(parsed),
      };
    }

    const structured = res.structuredContent;
    const rawEvidenceId =
      typeof structured?.evidence_id === "string" ? structured.evidence_id : null;
    let sanitizedData = structured;
    if (structured?.evidence_id) {
      const entry = this.recordEvidence(tenantId, structured, label, category, extraPaths);
      sanitizedData = entry ? entry.evidence : this.sanitizeForTenant(tenantId, structured, extraPaths);
    } else if (structured) {
      sanitizedData = scrubValue(structured);
    }
    return {
      ok: true,
      elapsed_ms: elapsedMs,
      raw_evidence_id: rawEvidenceId,
      data: sanitizedData,
    };
  }

  // =========================================================================
  // TAB 1: Electron & JavaScript Application Attack-Surface X-Ray
  // =========================================================================
  async scanJavaScriptApplication(tenantId, targetPath, label = null) {
    assertTenantId(tenantId);
    const resolvedPath = resolve(targetPath);
    const artifactLabel = label || basename(resolvedPath);
    const res = await this.callMcpTool(
      tenantId,
      "analyze_javascript_application",
      {
        input_path: resolvedPath,
        format: "auto",
        integrity_policy: "record-and-continue",
      },
      artifactLabel,
      "electron-xray",
      [resolvedPath],
    );
    if (!res.ok) return res;

    this.metrics.scans_completed += 1;
    const evidence = res.data;
    const posture = evaluateJavaScriptSecurityPosture(evidence);
    const key = this.ledgerKey(tenantId, evidence.evidence_id);
    const entry = getBoundedMap(this.evidenceLedger, key);
    if (entry) entry.posture = posture;

    const summaryPayload = {
      ok: true,
      elapsed_ms: res.elapsed_ms,
      evidence_id: evidence.evidence_id,
      artifact_name: artifactLabel,
      root_artifact_sha256: evidence.normalized_result.root_artifact_sha256,
      summary: evidence.normalized_result.summary,
      statistics: evidence.normalized_result.statistics,
      route_inventory: evidence.normalized_result.route_inventory ?? null,
      semantic_families: (evidence.normalized_result.semantic_graph?.coverage?.families ?? []).filter(
        (f) => f.retained_relations > 0 || f.unknown_ids?.length > 0,
      ),
      limitations: evidence.limitations ?? [],
      posture,
    };
    setTenantFairBoundedMap(
      this.jsScansByTarget,
      tenantId,
      key,
      summaryPayload,
      this.maxJsScans,
      this.maxJsScansPerTenant,
    );
    return summaryPayload;
  }

  async traceJavaScriptFeature(
    tenantId,
    evidenceId,
    seedKind,
    seedValue,
    direction = "both",
    match = "contains",
  ) {
    assertTenantId(tenantId);
    const owned = evidenceId ? this.getEvidenceRecord(tenantId, evidenceId) : null;
    if (!owned) {
      return {
        ok: false,
        status: 404,
        error: {
          code: "evidence_not_found",
          message: "Evidence envelope not found in active workspace.",
        },
      };
    }

    const inlineEvidence = this.exportSchemaValidEvidence(owned);
    const res = await this.callMcpTool(
      tenantId,
      "trace_application_feature",
      {
        application: inlineEvidence,
        seed: {
          kind: seedKind,
          value: seedValue,
          match,
          case_sensitive: false,
        },
        direction,
      },
      `trace:${seedKind}:${seedValue}`,
      "feature-trace",
    );
    if (!res.ok) return res;
    return {
      ok: true,
      elapsed_ms: res.elapsed_ms,
      evidence_id: res.data.evidence_id,
      trace: res.data.normalized_result,
      limitations: res.data.limitations ?? [],
    };
  }

  async compareJavaScriptVersions(tenantId, leftPathOrEvId, rightPathOrEvId) {
    assertTenantId(tenantId);
    const resolveSide = async (val, label) => {
      if (typeof val === "string" && val.startsWith("ev_")) {
        const owned = this.getEvidenceRecord(tenantId, val);
        if (!owned) {
          return {
            ok: false,
            status: 404,
            error: {
              code: "evidence_not_found",
              message: "Referenced Evidence envelope not found in active workspace.",
            },
          };
        }
        return {
          ok: true,
          evidenceId: owned.evidence_id,
          inlineEvidence: this.exportSchemaValidEvidence(owned),
          scan: getBoundedMap(this.jsScansByTarget, this.ledgerKey(tenantId, owned.evidence_id)) ?? null,
        };
      }
      const scanned = await this.scanJavaScriptApplication(tenantId, val, label);
      if (!scanned.ok) {
        return {
          ok: false,
          status: 422,
          error: { message: scanned.error?.message || "Failed to scan version" },
        };
      }
      const owned = this.getEvidenceRecord(tenantId, scanned.evidence_id);
      return {
        ok: true,
        evidenceId: scanned.evidence_id,
        inlineEvidence: this.exportSchemaValidEvidence(owned),
        scan: scanned,
      };
    };

    const left = await resolveSide(leftPathOrEvId, "Baseline Version");
    if (!left.ok) return left;
    const right = await resolveSide(rightPathOrEvId, "Candidate Version");
    if (!right.ok) return right;

    const cmp = await this.callMcpTool(
      tenantId,
      "compare_application_versions",
      {
        left: left.inlineEvidence,
        right: right.inlineEvidence,
      },
      "release-version-diff",
      "version-diff",
    );
    if (!cmp.ok) return cmp;

    return {
      ok: true,
      elapsed_ms: cmp.elapsed_ms,
      evidence_id: cmp.data.evidence_id,
      left_posture: left.scan?.posture ?? null,
      right_posture: right.scan?.posture ?? null,
      comparison: cmp.data.normalized_result,
    };
  }

  // =========================================================================
  // TAB 2: ShipGate — Binary, AI Model, EVM Contract & Bytecode Supply-Chain Gate
  // =========================================================================
  detectArtifactKind(filePath, categoryHint = null) {
    if (categoryHint && categoryHint !== "auto") return categoryHint;
    const ext = extname(filePath).toLowerCase();
    if (ext === ".safetensors" || ext === ".gguf") return "ai-model";
    if (ext === ".pyc") return "python-pyc";
    if (ext === ".hex" || ext === ".evm") return "evm-bytecode";
    if (ext === ".apk" || ext === ".aab") return "apk-package";
    if (ext === ".beam") return "erlang-beam";

    const buf = Buffer.alloc(16);
    try {
      const bytes = readFileSync(filePath);
      bytes.copy(buf, 0, 0, Math.min(16, bytes.length));
      if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
        return ext === ".ko" ? "kernel-module" : "elf-binary";
      }
      if (buf[0] === 0x4d && buf[1] === 0x5a) return "pe-binary";
      if (buf.toString("ascii", 0, 4) === "GGUF") return "ai-model";
      if (buf[0] === 0x50 && buf[1] === 0x4b) return "apk-package";
      const headText = bytes.subarray(0, Math.min(256, bytes.length)).toString("utf8").trim();
      if (/^(0x)?[0-9a-fA-F]{16,}$/.test(headText)) return "evm-bytecode";
    } catch {
      // fallback
    }
    return "generic-binary";
  }

  async inspectShipGateArtifact(tenantId, filePath, categoryHint = "auto", options = {}) {
    assertTenantId(tenantId);
    const resolvedPath = resolve(filePath);
    const stat = statSync(resolvedPath);
    const rawBytes = readFileSync(resolvedPath);
    const sha256 = createHash("sha256").update(rawBytes).digest("hex");
    const kind = this.detectArtifactKind(resolvedPath, categoryHint);
    const t0 = Date.now();
    const label = options.label || basename(resolvedPath);
    const extraPaths = [resolvedPath];

    const entropyRes = await this.callMcpTool(
      tenantId,
      "inspect_byte_entropy",
      { path: resolvedPath, block_size: stat.size > 32768 ? 4096 : 256 },
      `${label}:entropy`,
      "shipgate",
      extraPaths,
    );

    const panels = {};
    const evidenceIds = [];
    if (entropyRes.ok) {
      panels.entropy = entropyRes.data.normalized_result;
      evidenceIds.push(entropyRes.data.evidence_id);
    }

    const explicitCategoryRequested =
      Boolean(categoryHint) && categoryHint !== "auto" && categoryHint !== "generic-binary";
    let explicitCategoryError = null;

    if (kind === "elf-binary" || kind === "kernel-module") {
      const safeSymbol =
        typeof options.symbol === "string" && /^[a-zA-Z0-9_.$@-]{1,128}$/.test(options.symbol)
          ? options.symbol
          : undefined;
      const [exportsRes, notesRes, goRes, rustRes, objdumpRes] = await Promise.all([
        this.callMcpTool(tenantId, "inspect_native_exports", { path: resolvedPath }, `${label}:exports`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_elf_notes", { path: resolvedPath }, `${label}:elf-notes`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_go_binary", { path: resolvedPath }, `${label}:go`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_rust_binary", { path: resolvedPath }, `${label}:rust`, "shipgate", extraPaths),
        this.callMcpTool(
          tenantId,
          "inspect_with_objdump",
          {
            path: resolvedPath,
            operation: "disassemble",
            ...(safeSymbol ? { symbol: safeSymbol } : {}),
          },
          `${label}:disassembly`,
          "shipgate",
          extraPaths,
        ),
      ]);

      if (exportsRes.ok) {
        panels.exports = exportsRes.data.normalized_result;
        evidenceIds.push(exportsRes.data.evidence_id);
      }
      if (notesRes.ok) {
        panels.elf_notes = notesRes.data.normalized_result;
        evidenceIds.push(notesRes.data.evidence_id);
      }
      if (goRes.ok && goRes.data.normalized_result?.go_version) {
        panels.go_metadata = goRes.data.normalized_result;
        evidenceIds.push(goRes.data.evidence_id);
      }
      if (rustRes.ok && rustRes.data.normalized_result?.packages?.length) {
        panels.rust_crates = rustRes.data.normalized_result;
        evidenceIds.push(rustRes.data.evidence_id);
      }
      if (objdumpRes.ok) {
        panels.disassembly = {
          stdout: objdumpRes.data.normalized_result.stdout,
          symbol: safeSymbol ?? null,
          truncated: objdumpRes.data.normalized_result.output_truncated ?? false,
        };
        evidenceIds.push(objdumpRes.data.evidence_id);
      }
      if (!exportsRes.ok && !notesRes.ok && !objdumpRes.ok) {
        explicitCategoryError = exportsRes.error || notesRes.error;
      }
    } else if (kind === "pe-binary") {
      const [impRes, certRes, cfgRes, goRes, rustRes] = await Promise.all([
        this.callMcpTool(tenantId, "inspect_pe_imports", { path: resolvedPath }, `${label}:pe-imports`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_pe_certificates", { path: resolvedPath }, `${label}:pe-certs`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_pe_load_config", { path: resolvedPath }, `${label}:pe-cfg`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_go_binary", { path: resolvedPath }, `${label}:go`, "shipgate", extraPaths),
        this.callMcpTool(tenantId, "inspect_rust_binary", { path: resolvedPath }, `${label}:rust`, "shipgate", extraPaths),
      ]);
      for (const [k, r] of [
        ["pe_imports", impRes],
        ["pe_certificates", certRes],
        ["pe_load_config", cfgRes],
        ["go_metadata", goRes],
        ["rust_crates", rustRes],
      ]) {
        if (r.ok) {
          panels[k] = r.data.normalized_result;
          evidenceIds.push(r.data.evidence_id);
        }
      }
      if (!impRes.ok && !certRes.ok && !cfgRes.ok) {
        explicitCategoryError = impRes.error;
      }
    } else if (kind === "ai-model") {
      await this.withPinnedTenantSession(tenantId, async () => {
        const modelRes = await this.callMcpTool(
          tenantId,
          "inspect_model_artifact",
          { path: resolvedPath, hash: "full" },
          `${label}:model`,
          "shipgate",
          extraPaths,
        );
        if (modelRes.ok) {
          evidenceIds.push(modelRes.data.evidence_id);
          const parentId =
            modelRes.raw_evidence_id || modelRes.data.normalized_result.parent_evidence_id;
          const [tensorsView, metaView] = await Promise.all([
            this.callMcpTool(
              tenantId,
              "inspect_analysis_view",
              {
                source: { kind: "retained-evidence", evidence_id: parentId },
                view: { kind: "model-artifact", collection: "tensors", offset: 0, limit: 64 },
              },
              `${label}:tensors`,
              "shipgate",
              extraPaths,
            ),
            this.callMcpTool(
              tenantId,
              "inspect_analysis_view",
              {
                source: { kind: "retained-evidence", evidence_id: parentId },
                view: { kind: "model-artifact", collection: "metadata", offset: 0, limit: 64 },
              },
              `${label}:metadata`,
              "shipgate",
              extraPaths,
            ),
          ]);
          panels.model = {
            summary: modelRes.data.normalized_result.summary,
            tensors: tensorsView.ok ? tensorsView.data.normalized_result.items : [],
            metadata: metaView.ok ? metaView.data.normalized_result.items : [],
            limitations: modelRes.data.normalized_result.limitations ?? [],
          };
        } else {
          explicitCategoryError = modelRes.error;
        }
      });
    } else if (kind === "evm-bytecode") {
      const cleanHex = rawBytes.toString("utf8").trim().replace(/^0x/i, "");
      let targetCarrier = resolvedPath;
      let tempCarrier = null;
      if (rawBytes.toString("utf8").trim().startsWith("0x")) {
        const tenantScratch = join(this.uploadsDir, tenantId);
        ensureSecureDirectory(tenantScratch);
        tempCarrier = join(tenantScratch, `normalized-${randomUUID()}.hex`);
        writeFileSync(tempCarrier, cleanHex, { mode: 0o600 });
        targetCarrier = tempCarrier;
      }
      try {
        const evmRes = await this.callMcpTool(
          tenantId,
          "inspect_evm_interface",
          { path: targetCarrier, encoding: "hex" },
          `${label}:evm`,
          "shipgate",
          tempCarrier ? [...extraPaths, tempCarrier] : extraPaths,
        );
        if (evmRes.ok) {
          const norm = evmRes.data.normalized_result;
          panels.evm = {
            ...norm,
            functions: enrichEvmFunctions(norm.functions ?? []),
          };
          evidenceIds.push(evmRes.data.evidence_id);
        } else {
          explicitCategoryError = evmRes.error;
        }
      } finally {
        if (tempCarrier) {
          rmSync(tempCarrier, { force: true });
        }
      }
    } else if (kind === "python-pyc") {
      const pycRes = await this.callMcpTool(
        tenantId,
        "inspect_python_pyc",
        { path: resolvedPath },
        `${label}:pyc`,
        "shipgate",
        extraPaths,
      );
      if (pycRes.ok) {
        panels.python_pyc = pycRes.data.normalized_result;
        evidenceIds.push(pycRes.data.evidence_id);
      } else {
        explicitCategoryError = pycRes.error;
      }
    } else if (kind === "apk-package") {
      const apkRes = await this.callMcpTool(
        tenantId,
        "inspect_apk_signature",
        { path: resolvedPath },
        `${label}:apk-sig`,
        "shipgate",
        extraPaths,
      );
      if (apkRes.ok) {
        panels.apk_signature = apkRes.data.normalized_result;
        evidenceIds.push(apkRes.data.evidence_id);
      } else {
        explicitCategoryError = apkRes.error;
      }
    } else if (kind === "erlang-beam") {
      const beamRes = await this.callMcpTool(
        tenantId,
        "inspect_erlang_beam",
        { path: resolvedPath },
        `${label}:beam`,
        "shipgate",
        extraPaths,
      );
      if (beamRes.ok) {
        panels.erlang_beam = beamRes.data.normalized_result;
        evidenceIds.push(beamRes.data.evidence_id);
      } else {
        explicitCategoryError = beamRes.error;
      }
    }

    if (explicitCategoryRequested && explicitCategoryError) {
      return {
        ok: false,
        status: 422,
        error: explicitCategoryError,
      };
    }
    if (evidenceIds.length === 0) {
      return {
        ok: false,
        status: 422,
        error: entropyRes.error || { code: "artifact_inspection_failed", message: "Artifact could not be inspected." },
      };
    }

    this.metrics.scans_completed += 1;
    return {
      ok: true,
      elapsed_ms: Date.now() - t0,
      artifact: {
        name: label,
        bytes: stat.size,
        sha256,
        detected_kind: kind,
      },
      evidence_ids: evidenceIds,
      panels,
    };
  }

  // =========================================================================
  // TAB 3: HAR-to-RL AgentEnv Factory + Tenant-Isolated Sandbox Server
  // =========================================================================
  async closeEnvironmentRecord(env) {
    if (!env) return;
    this.liveEnvironments.delete(env.env_id);
    try {
      await env.envClient.close();
      env.abortController.abort();
      await env.served.close();
    } catch {
      // ignore teardown errors
    }
    try {
      rmSync(env.bundle_dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }

  async reapIdleEnvironments(maxIdleMs = this.rlIdleTtlMs) {
    const now = Date.now();
    let reaped = 0;
    for (const env of [...this.liveEnvironments.values()]) {
      const lastActive = Number(env.last_active_at || 0);
      if (now - lastActive >= maxIdleMs) {
        await this.closeEnvironmentRecord(env);
        reaped += 1;
        this.metrics.rl_idle_reaped += 1;
      }
    }
    await this.reapIdleTenantSessions();
    return reaped;
  }

  async enforceTenantSandboxCap(tenantId) {
    await this.reapIdleEnvironments();
    const owned = [...this.liveEnvironments.values()].filter((e) => e.tenant_id === tenantId);
    while (owned.length >= this.maxTenantLiveEnvs) {
      const oldest = owned.shift();
      await this.closeEnvironmentRecord(oldest);
    }

    // Enforce global live RL server cap across all tenants without letting one tenant starve others
    while (this.liveEnvironments.size >= this.maxGlobalLiveEnvs) {
      const byOwner = new Map();
      for (const env of this.liveEnvironments.values()) {
        const list = byOwner.get(env.tenant_id) || [];
        list.push(env);
        byOwner.set(env.tenant_id, list);
      }

      // If any tenant currently holds >1 active sandbox, reclaim the oldest excess sandbox from the largest holder
      let multiHolderOldest = null;
      let maxHeld = 1;
      for (const list of byOwner.values()) {
        if (list.length > maxHeld) {
          maxHeld = list.length;
          multiHolderOldest = list[0];
        }
      }
      if (multiHolderOldest) {
        await this.closeEnvironmentRecord(multiHolderOldest);
        continue;
      }

      return {
        ok: false,
        status: 503,
        error: {
          code: "global_rl_capacity_reached",
          message:
            "Global live AgentEnv sandbox capacity reached across active workspaces. Retry shortly after idle sandboxes expire.",
        },
      };
    }

    return { ok: true };
  }

  getAuthorizedEnvironment(tenantId, envId) {
    if (!tenantId || !envId) return null;
    const env = this.liveEnvironments.get(String(envId));
    if (!env || env.tenant_id !== tenantId) return null;
    if (Date.now() - Number(env.last_active_at || 0) >= this.rlIdleTtlMs) {
      void this.closeEnvironmentRecord(env);
      return null;
    }
    env.last_active_at = Date.now();
    return env;
  }

  sanitizeBundleEvidenceFiles(tenantId, bundleDir, safeName, extraPaths = []) {
    const manifestPath = join(bundleDir, "envs", safeName, "manifest.json");
    const evidencePath = join(bundleDir, "envs", safeName, "evidence.json");
    const rawManifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const rawEvidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    const oldEvidenceId = rawEvidence.evidence_id;
    const oldManifestId = rawManifest.evidence_id;

    const cleanEvidence = sanitizeEvidenceEnvelope(rawEvidence, {
      repoRoot: this.repoRoot,
      runtimeDir: this.runtimeDir,
      extraPaths,
      tenantId,
      keepSchemaLocalPath: true,
    });
    this.sealRedactedEvidence(cleanEvidence, oldEvidenceId);

    let cleanManifest = sanitizeEvidenceEnvelope(rawManifest, {
      repoRoot: this.repoRoot,
      runtimeDir: this.runtimeDir,
      extraPaths,
      tenantId,
      keepSchemaLocalPath: true,
    });

    if (cleanEvidence.evidence_id !== oldEvidenceId) {
      cleanManifest = JSON.parse(
        JSON.stringify(cleanManifest).split(oldEvidenceId).join(cleanEvidence.evidence_id),
      );
    }
    this.sealRedactedEvidence(cleanManifest, oldManifestId);

    writeFileSync(evidencePath, `${JSON.stringify(cleanEvidence, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(manifestPath, `${JSON.stringify(cleanManifest, null, 2)}\n`, { mode: 0o600 });

    return { manifestJson: cleanManifest, evidenceJson: cleanEvidence };
  }

  async buildAndServeAgentEnvironment(tenantId, harPath, requestedName = "custom-env") {
    assertTenantId(tenantId);
    const capCheck = await this.enforceTenantSandboxCap(tenantId);
    if (capCheck && !capCheck.ok) return capCheck;

    const resolvedHar = resolve(harPath);
    const safeName =
      String(requestedName || "agent-env")
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48) || "agent-env";

    const t0 = Date.now();
    const buildId = `${safeName}-${randomUUID().slice(0, 12)}`;
    const tenantBundleParent = join(this.bundlesDir, tenantId);
    ensureSecureDirectory(tenantBundleParent);
    const bundleDir = join(tenantBundleParent, buildId);

    const { capRes, exportRes } = await this.withPinnedTenantSession(tenantId, async () => {
      const cap = await this.callMcpTool(
        tenantId,
        "inspect_web_network_capture",
        { capture_path: resolvedHar, format: "har" },
        `${safeName}.har`,
        "rl-capture",
        [resolvedHar],
      );
      if (!cap.ok) return { capRes: cap, exportRes: null };

      const retainedCaptureId = cap.raw_evidence_id || cap.data.evidence_id;
      const exp = await this.callMcpTool(
        tenantId,
        "export_environment_bundle",
        {
          source: { kind: "retained-evidence", evidence_id: retainedCaptureId },
          output_directory: bundleDir,
          name: safeName,
        },
        `bundle:${safeName}`,
        "rl-bundle",
        [resolvedHar, bundleDir],
      );
      return { capRes: cap, exportRes: exp };
    });
    if (!capRes.ok) return capRes;
    if (!exportRes.ok) {
      rmSync(bundleDir, { recursive: true, force: true });
      return exportRes;
    }

    const { scrubValue } = createPathScrubber({
      repoRoot: this.repoRoot,
      runtimeDir: this.runtimeDir,
      extraPaths: [resolvedHar, bundleDir],
      tenantId,
    });
    const report = scrubValue(exportRes.data);
    if (report && typeof report === "object" && "output_directory" in report) {
      report.output_directory = `${safeName}-bundle`;
    }
    this.metrics.rl_bundles_built += 1;

    const { manifestJson, evidenceJson } = this.sanitizeBundleEvidenceFiles(
      tenantId,
      bundleDir,
      safeName,
      [resolvedHar, bundleDir],
    );

    this.recordEvidence(tenantId, manifestJson, `${safeName}:manifest`, "rl-manifest", [
      resolvedHar,
      bundleDir,
    ]);

    const sourceLoaded = this.distMod.loadEnvironmentSource(manifestJson, evidenceJson);
    if (!sourceLoaded.ok) {
      return { ok: false, error: { message: sourceLoaded.error.message } };
    }
    const servedState = this.distMod.prepareServedState(sourceLoaded.value, evidenceJson, {
      name: safeName,
    });

    const abortController = new AbortController();
    const started = await this.distMod.serveEnvironment({
      source: sourceLoaded.value,
      ...(servedState.state === undefined ? {} : { state: servedState.state }),
      signal: abortController.signal,
      host: "127.0.0.1",
      port: 0,
      environmentName: safeName,
      logger: this.distMod.silentLogger,
      onerror: () => {},
    });
    if (!started.ok) {
      return { ok: false, error: { message: started.error.message } };
    }

    const served = started.value;
    const mcpUrl = new URL(served.url);
    const agentEnvRpcUrl = new URL("/agentenv", mcpUrl.origin).toString();

    const envClient = new Client(
      { name: "studio-rl-sandbox", version: "1.0.0" },
      { jsonSchemaValidator: NOOP_VALIDATOR },
    );
    await envClient.connect(new StreamableHTTPClientTransport(mcpUrl));
    const listedTools = await envClient.listTools();

    const nowMs = Date.now();
    const envRecord = {
      env_id: buildId,
      tenant_id: tenantId,
      name: safeName,
      bundle_dir: bundleDir,
      mcp_url: served.url,
      rpc_url: agentEnvRpcUrl,
      abortController,
      served,
      envClient,
      report,
      tools: listedTools.tools,
      custom_tasks: [],
      created_at: new Date(nowMs).toISOString(),
      last_active_at: nowMs,
    };
    this.liveEnvironments.set(buildId, envRecord);

    const stateSnapshot = await this.fetchAgentEnvState(tenantId, buildId);
    const bundleFiles = this.readBundleTextFiles(bundleDir);

    return {
      ok: true,
      elapsed_ms: Date.now() - t0,
      env_id: buildId,
      name: safeName,
      report,
      tools: listedTools.tools,
      state_snapshot: stateSnapshot,
      bundle_files: bundleFiles,
      custom_tasks: [],
    };
  }

  readBundleTextFiles(bundleDir) {
    const out = [];
    const walk = (dir) => {
      for (const name of readdirSync(dir).sort()) {
        const full = join(dir, name);
        const st = statSync(full);
        if (st.isDirectory()) {
          walk(full);
        } else if (st.isFile()) {
          const rel = relative(bundleDir, full).split("\\").join("/");
          const isLargeEvidence = rel.endsWith("evidence.json") && st.size > 40000;
          out.push({
            path: rel,
            bytes: st.size,
            preview: isLargeEvidence
              ? readFileSync(full, "utf8").slice(0, 4000) +
                "\n/* ... truncated in preview; full file included in .zip download ... */"
              : readFileSync(full, "utf8"),
          });
        }
      }
    };
    walk(bundleDir);
    return out;
  }

  async fetchAgentEnvState(tenantId, envId) {
    const env = this.getAuthorizedEnvironment(tenantId, envId);
    if (!env) return null;
    try {
      const resp = await fetch(env.rpc_url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "data/get", params: {} }),
      });
      if (!resp.ok) return null;
      const body = await resp.json();
      return body?.result?.parts?.[0]?.data ?? null;
    } catch {
      return null;
    }
  }

  async callLiveAgentTool(tenantId, envId, toolName, args = {}) {
    const env = this.getAuthorizedEnvironment(tenantId, envId);
    if (!env) {
      return { ok: false, status: 404, error: { message: "Environment not found in active workspace." } };
    }

    const t0 = Date.now();
    const res = await env.envClient.callTool({ name: toolName, arguments: args });
    this.metrics.rl_tool_calls += 1;

    const rawText = res.content?.find((c) => c.type === "text")?.text ?? "{}";
    let parsedOutput = rawText;
    try {
      parsedOutput = JSON.parse(rawText);
    } catch {
      // keep string
    }
    const stateSnapshot = await this.fetchAgentEnvState(tenantId, envId);
    return {
      ok: !res.isError,
      elapsed_ms: Date.now() - t0,
      tool: toolName,
      result: parsedOutput,
      state_snapshot: stateSnapshot,
    };
  }

  async resetLiveAgentState(tenantId, envId) {
    const env = this.getAuthorizedEnvironment(tenantId, envId);
    if (!env) {
      return { ok: false, status: 404, error: { message: "Environment not found in active workspace." } };
    }

    await fetch(env.rpc_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "data/reset", params: {} }),
    });
    const stateSnapshot = await this.fetchAgentEnvState(tenantId, envId);
    return { ok: true, state_snapshot: stateSnapshot };
  }

  async evaluateAndSaveRlTask(tenantId, envId, taskInput) {
    const env = this.getAuthorizedEnvironment(tenantId, envId);
    if (!env) {
      return { ok: false, status: 404, error: { message: "Environment not found in active workspace." } };
    }

    const stateSnapshot = await this.fetchAgentEnvState(tenantId, envId);
    const collections = this.extractStateCollections(stateSnapshot);

    const assertions = Array.isArray(taskInput.assertions) ? taskInput.assertions.slice(0, 32) : [];
    const results = assertions.map((assertion) => {
      const items = collections[assertion.collection] ?? [];
      const field = String(assertion.field || "").trim();
      const expected = String(assertion.expected ?? "").trim();
      const operator = assertion.operator || "equals";

      let matched = false;
      if (operator === "not_exists") {
        matched = !items.some((item) => String(item?.[field] ?? "") === expected);
      } else if (operator === "contains") {
        matched = items.some((item) =>
          String(item?.[field] ?? "")
            .toLowerCase()
            .includes(expected.toLowerCase()),
        );
      } else {
        matched = items.some((item) => String(item?.[field] ?? "") === expected);
      }

      return {
        collection: assertion.collection,
        field,
        operator,
        expected,
        passed: matched,
        observed_count: items.length,
      };
    });

    const passedCount = results.filter((r) => r.passed).length;
    const reward = results.length === 0 ? 1.0 : Number((passedCount / results.length).toFixed(3));

    const taskSlug =
      String(taskInput.id || taskInput.title || "custom-task")
        .toLowerCase()
        .replace(/[^a-z0-9-_]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48) || "custom-task";

    const taskDocument = {
      id: taskSlug,
      environment: env.name,
      prompt: String(taskInput.prompt || "Complete the requested operation in the environment.").slice(0, 2000),
      reset_before_run: true,
      verifier: {
        kind: "rea-state-assertions/v1",
        assertions,
      },
      created_at: new Date().toISOString(),
    };

    if (taskInput.save !== false) {
      const tasksDir = join(env.bundle_dir, "tasks");
      ensureSecureDirectory(tasksDir);
      writeFileSync(join(tasksDir, `${taskSlug}.json`), JSON.stringify(taskDocument, null, 2), {
        mode: 0o600,
      });
      const existingIdx = env.custom_tasks.findIndex((t) => t.id === taskSlug);
      if (existingIdx >= 0) env.custom_tasks[existingIdx] = taskDocument;
      else env.custom_tasks.push(taskDocument);
    }

    return {
      ok: true,
      reward,
      passed: reward === 1,
      checks: results,
      task: taskDocument,
      bundle_files: this.readBundleTextFiles(env.bundle_dir),
    };
  }

  extractStateCollections(stateSnapshot) {
    const map = {};
    const entities = stateSnapshot?.rea_state?.entities;
    if (Array.isArray(entities)) {
      for (const ent of entities) {
        const col = ent?.collection || ent?.type || "default";
        if (!map[col]) map[col] = [];
        map[col].push({ id: ent.id, ...(ent.fields || {}) });
      }
      return map;
    }
    const docs = stateSnapshot?.rea_state?.documents;
    if (Array.isArray(docs)) {
      for (const doc of docs) {
        const col = doc?.path || "documents";
        if (!map[col]) map[col] = [];
        map[col].push(doc.value ?? doc);
      }
    }
    return map;
  }

  listEvidence(tenantId) {
    if (!tenantId || typeof tenantId !== "string") return [];
    return [...this.evidenceLedger.values()]
      .filter((entry) => entry.tenant_id === tenantId)
      .reverse()
      .map(({ evidence: _ev, posture, tenant_id: _tid, ...meta }) => ({
        ...meta,
        score: posture?.score ?? null,
        grade: posture?.grade ?? null,
      }));
  }

  getEvidenceRecord(tenantId, evidenceId) {
    if (!tenantId || !evidenceId) return null;
    const direct = getBoundedMap(this.evidenceLedger, this.ledgerKey(tenantId, evidenceId));
    if (direct) return direct;
    const mappedId = this.evidenceIdAliases.get(this.ledgerKey(tenantId, evidenceId));
    if (mappedId) {
      return getBoundedMap(this.evidenceLedger, this.ledgerKey(tenantId, mappedId)) ?? null;
    }
    return null;
  }

  async close() {
    for (const env of [...this.liveEnvironments.values()]) {
      await this.closeEnvironmentRecord(env);
    }
    this.liveEnvironments.clear();
    for (const slot of [...this.tenantSessions.values()]) {
      await this.destroyMcpSlot(slot);
    }
    this.tenantSessions.clear();
    rmSync(this.bundlesDir, { recursive: true, force: true });
  }
}
