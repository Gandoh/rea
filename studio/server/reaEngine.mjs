import { randomUUID, createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
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

/**
 * Persistent in-process REA Engine Bridge + Live AgentEnv Sandbox Supervisor.
 */
export class ReaStudioEngine {
  constructor(repoRoot, runtimeDir) {
    this.repoRoot = repoRoot;
    this.runtimeDir = runtimeDir;
    this.bundlesDir = join(runtimeDir, "bundles");
    this.uploadsDir = join(runtimeDir, "uploads");
    mkdirSync(this.bundlesDir, { recursive: true });
    mkdirSync(this.uploadsDir, { recursive: true });

    this.client = null;
    this.server = null;
    this.session = null;
    this.distMod = null;
    this.toolCount = 0;

    /** @type {Map<string, object>} */
    this.evidenceLedger = new Map();
    /** @type {Map<string, object>} */
    this.jsScansByTarget = new Map();
    /** @type {Map<string, object>} */
    this.liveEnvironments = new Map();

    this.metrics = {
      scans_completed: 0,
      evidence_sealed: 0,
      rl_bundles_built: 0,
      rl_tool_calls: 0,
      api_requests: 0,
      started_at: new Date().toISOString(),
    };
  }

  async init() {
    if (this.client) return;
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
    ] = await Promise.all([
      import(join(distRoot, "composition/binary.js")),
      import(join(distRoot, "config/parseConfig.js")),
      import(join(distRoot, "logger.js")),
      import(join(distRoot, "server/createServer.js")),
      import(join(distRoot, "application/environment/environmentSource.js")),
      import(join(distRoot, "application/environment/environmentState.js")),
      import(join(distRoot, "server/environment/serveEnvironment.js")),
    ]);

    this.distMod = {
      silentLogger,
      loadEnvironmentSource,
      prepareServedState,
      serveEnvironment,
    };

    const configured = parseConfig({ REA_ANALYSIS_PROVIDER: "auto" });
    if (!configured.ok) throw configured.error;

    this.session = createBinarySession(configured.value, silentLogger, process.env);
    this.server = createServer({ kind: "session", session: this.session });
    this.client = new Client(
      { name: "rea-cloud-studio", version: "1.0.0" },
      { jsonSchemaValidator: NOOP_VALIDATOR },
    );

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await this.server.connect(serverTransport);
    await this.client.connect(clientTransport);

    const catalog = await this.client.listTools();
    this.toolCount = catalog.tools.length;
  }

  recordEvidence(evidence, label, category) {
    if (!evidence || typeof evidence.evidence_id !== "string") return null;
    const entry = {
      evidence_id: evidence.evidence_id,
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
    if (!this.evidenceLedger.has(evidence.evidence_id)) {
      this.metrics.evidence_sealed += 1;
    }
    this.evidenceLedger.set(evidence.evidence_id, entry);
    return entry;
  }

  async callMcpTool(name, args, label = null, category = "analysis") {
    await this.init();
    const t0 = Date.now();
    const res = await this.client.callTool({ name, arguments: args });
    const elapsedMs = Date.now() - t0;

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
        error: parsed,
      };
    }

    const structured = res.structuredContent;
    if (structured?.evidence_id) {
      this.recordEvidence(structured, label, category);
    }
    return {
      ok: true,
      elapsed_ms: elapsedMs,
      data: structured,
    };
  }

  // =========================================================================
  // TAB 1: Electron & JavaScript Application Attack-Surface X-Ray
  // =========================================================================
  async scanJavaScriptApplication(targetPath, label = null) {
    const resolvedPath = resolve(targetPath);
    const res = await this.callMcpTool(
      "analyze_javascript_application",
      {
        input_path: resolvedPath,
        format: "auto",
        integrity_policy: "record-and-continue",
      },
      label || basename(resolvedPath),
      "electron-xray",
    );
    if (!res.ok) return res;

    this.metrics.scans_completed += 1;
    const evidence = res.data;
    const posture = evaluateJavaScriptSecurityPosture(evidence);
    const entry = this.evidenceLedger.get(evidence.evidence_id);
    if (entry) entry.posture = posture;

    const summaryPayload = {
      ok: true,
      elapsed_ms: res.elapsed_ms,
      evidence_id: evidence.evidence_id,
      target_path: resolvedPath,
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
    this.jsScansByTarget.set(evidence.evidence_id, summaryPayload);
    return summaryPayload;
  }

  async traceJavaScriptFeature(evidenceId, seedKind, seedValue, direction = "both", match = "contains") {
    const res = await this.callMcpTool(
      "trace_application_feature",
      {
        application: { kind: "retained-evidence", evidence_id: evidenceId },
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

  async compareJavaScriptVersions(leftPathOrEvId, rightPathOrEvId) {
    const resolveSide = async (val, label) => {
      if (typeof val === "string" && val.startsWith("ev_")) {
        return { evidenceId: val, scan: this.jsScansByTarget.get(val) ?? null };
      }
      const scanned = await this.scanJavaScriptApplication(val, label);
      if (!scanned.ok) throw new Error(scanned.error?.message || "Failed to scan version");
      return { evidenceId: scanned.evidence_id, scan: scanned };
    };

    const left = await resolveSide(leftPathOrEvId, "Baseline Version");
    const right = await resolveSide(rightPathOrEvId, "Candidate Version");

    const cmp = await this.callMcpTool(
      "compare_application_versions",
      {
        left: { kind: "retained-evidence", evidence_id: left.evidenceId },
        right: { kind: "retained-evidence", evidence_id: right.evidenceId },
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
      // Check if pure hex text (EVM bytecode)
      const headText = bytes.subarray(0, Math.min(256, bytes.length)).toString("utf8").trim();
      if (/^(0x)?[0-9a-fA-F]{16,}$/.test(headText)) return "evm-bytecode";
    } catch {
      // fallback
    }
    return "generic-binary";
  }

  async inspectShipGateArtifact(filePath, categoryHint = "auto", options = {}) {
    const resolvedPath = resolve(filePath);
    const stat = statSync(resolvedPath);
    const rawBytes = readFileSync(resolvedPath);
    const sha256 = createHash("sha256").update(rawBytes).digest("hex");
    const kind = this.detectArtifactKind(resolvedPath, categoryHint);
    const t0 = Date.now();
    const label = basename(resolvedPath);

    // Always run byte entropy for visual block entropy chart
    const entropyRes = await this.callMcpTool(
      "inspect_byte_entropy",
      { path: resolvedPath, block_size: stat.size > 32768 ? 4096 : 256 },
      `${label}:entropy`,
      "shipgate",
    );

    const panels = {};
    const evidenceIds = [];
    if (entropyRes.ok) {
      panels.entropy = entropyRes.data.normalized_result;
      evidenceIds.push(entropyRes.data.evidence_id);
    }

    if (kind === "elf-binary" || kind === "kernel-module") {
      const [exportsRes, notesRes, goRes, rustRes, objdumpRes] = await Promise.all([
        this.callMcpTool("inspect_native_exports", { path: resolvedPath }, `${label}:exports`, "shipgate"),
        this.callMcpTool("inspect_elf_notes", { path: resolvedPath }, `${label}:elf-notes`, "shipgate"),
        this.callMcpTool("inspect_go_binary", { path: resolvedPath }, `${label}:go`, "shipgate"),
        this.callMcpTool("inspect_rust_binary", { path: resolvedPath }, `${label}:rust`, "shipgate"),
        this.callMcpTool(
          "inspect_with_objdump",
          {
            path: resolvedPath,
            operation: "disassemble",
            ...(options.symbol ? { symbol: options.symbol } : {}),
          },
          `${label}:disassembly`,
          "shipgate",
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
          symbol: options.symbol ?? null,
          truncated: objdumpRes.data.normalized_result.output_truncated ?? false,
        };
        evidenceIds.push(objdumpRes.data.evidence_id);
      }
    } else if (kind === "pe-binary") {
      const [impRes, certRes, cfgRes, goRes, rustRes] = await Promise.all([
        this.callMcpTool("inspect_pe_imports", { path: resolvedPath }, `${label}:pe-imports`, "shipgate"),
        this.callMcpTool("inspect_pe_certificates", { path: resolvedPath }, `${label}:pe-certs`, "shipgate"),
        this.callMcpTool("inspect_pe_load_config", { path: resolvedPath }, `${label}:pe-cfg`, "shipgate"),
        this.callMcpTool("inspect_go_binary", { path: resolvedPath }, `${label}:go`, "shipgate"),
        this.callMcpTool("inspect_rust_binary", { path: resolvedPath }, `${label}:rust`, "shipgate"),
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
    } else if (kind === "ai-model") {
      const modelRes = await this.callMcpTool(
        "inspect_model_artifact",
        { path: resolvedPath, hash: "full" },
        `${label}:model`,
        "shipgate",
      );
      if (modelRes.ok) {
        evidenceIds.push(modelRes.data.evidence_id);
        const parentId = modelRes.data.normalized_result.parent_evidence_id;
        const [tensorsView, metaView] = await Promise.all([
          this.callMcpTool(
            "inspect_analysis_view",
            {
              source: { kind: "retained-evidence", evidence_id: parentId },
              view: { kind: "model-artifact", collection: "tensors", offset: 0, limit: 64 },
            },
            `${label}:tensors`,
            "shipgate",
          ),
          this.callMcpTool(
            "inspect_analysis_view",
            {
              source: { kind: "retained-evidence", evidence_id: parentId },
              view: { kind: "model-artifact", collection: "metadata", offset: 0, limit: 64 },
            },
            `${label}:metadata`,
            "shipgate",
          ),
        ]);
        panels.model = {
          summary: modelRes.data.normalized_result.summary,
          tensors: tensorsView.ok ? tensorsView.data.normalized_result.items : [],
          metadata: metaView.ok ? metaView.data.normalized_result.items : [],
          limitations: modelRes.data.normalized_result.limitations ?? [],
        };
      }
    } else if (kind === "evm-bytecode") {
      const cleanHex = rawBytes.toString("utf8").trim().replace(/^0x/i, "");
      let targetCarrier = resolvedPath;
      if (rawBytes.toString("utf8").trim().startsWith("0x")) {
        targetCarrier = join(this.uploadsDir, `normalized-${Date.now()}.hex`);
        writeFileSync(targetCarrier, cleanHex);
      }
      const evmRes = await this.callMcpTool(
        "inspect_evm_interface",
        { path: targetCarrier, encoding: "hex" },
        `${label}:evm`,
        "shipgate",
      );
      if (evmRes.ok) {
        const norm = evmRes.data.normalized_result;
        panels.evm = {
          ...norm,
          functions: enrichEvmFunctions(norm.functions ?? []),
        };
        evidenceIds.push(evmRes.data.evidence_id);
      }
    } else if (kind === "python-pyc") {
      const pycRes = await this.callMcpTool(
        "inspect_python_pyc",
        { path: resolvedPath },
        `${label}:pyc`,
        "shipgate",
      );
      if (pycRes.ok) {
        panels.python_pyc = pycRes.data.normalized_result;
        evidenceIds.push(pycRes.data.evidence_id);
      }
    } else if (kind === "apk-package") {
      const apkRes = await this.callMcpTool(
        "inspect_apk_signature",
        { path: resolvedPath },
        `${label}:apk-sig`,
        "shipgate",
      );
      if (apkRes.ok) {
        panels.apk_signature = apkRes.data.normalized_result;
        evidenceIds.push(apkRes.data.evidence_id);
      }
    } else if (kind === "erlang-beam") {
      const beamRes = await this.callMcpTool(
        "inspect_erlang_beam",
        { path: resolvedPath },
        `${label}:beam`,
        "shipgate",
      );
      if (beamRes.ok) {
        panels.erlang_beam = beamRes.data.normalized_result;
        evidenceIds.push(beamRes.data.evidence_id);
      }
    }

    this.metrics.scans_completed += 1;
    return {
      ok: true,
      elapsed_ms: Date.now() - t0,
      artifact: {
        name: label,
        path: resolvedPath,
        bytes: stat.size,
        sha256,
        detected_kind: kind,
      },
      evidence_ids: evidenceIds,
      panels,
    };
  }

  // =========================================================================
  // TAB 3: HAR-to-RL AgentEnv Factory + Live Stateful Sandbox Server
  // =========================================================================
  async buildAndServeAgentEnvironment(harPath, requestedName = "custom-env") {
    const resolvedHar = resolve(harPath);
    const safeName =
      String(requestedName || "agent-env")
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48) || "agent-env";

    const t0 = Date.now();
    // 1. Inspect HAR via REA MCP
    const capRes = await this.callMcpTool(
      "inspect_web_network_capture",
      { capture_path: resolvedHar, format: "har" },
      `${safeName}.har`,
      "rl-capture",
    );
    if (!capRes.ok) return capRes;

    const captureEvidenceId = capRes.data.evidence_id;
    const buildId = `${safeName}-${randomUUID().slice(0, 8)}`;
    const bundleDir = join(this.bundlesDir, buildId);

    // 2. Build & export complete runnable AgentEnv bundle
    const exportRes = await this.callMcpTool(
      "export_environment_bundle",
      {
        source: { kind: "retained-evidence", evidence_id: captureEvidenceId },
        output_directory: bundleDir,
        name: safeName,
      },
      `bundle:${safeName}`,
      "rl-bundle",
    );
    if (!exportRes.ok) return exportRes;

    const report = exportRes.data;
    this.metrics.rl_bundles_built += 1;

    // 3. Spin up LIVE REA serveEnvironment instance so user can test tools & state in Studio!
    const manifestPath = join(bundleDir, "envs", safeName, "manifest.json");
    const evidencePath = join(bundleDir, "envs", safeName, "evidence.json");
    const manifestJson = JSON.parse(readFileSync(manifestPath, "utf8"));
    const evidenceJson = JSON.parse(readFileSync(evidencePath, "utf8"));

    this.recordEvidence(manifestJson, `${safeName}:manifest`, "rl-manifest");

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

    const envRecord = {
      env_id: buildId,
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
      created_at: new Date().toISOString(),
    };
    this.liveEnvironments.set(buildId, envRecord);

    const stateSnapshot = await this.fetchAgentEnvState(buildId);
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
              ? readFileSync(full, "utf8").slice(0, 4000) + "\n/* ... truncated in preview; full file included in .zip download ... */"
              : readFileSync(full, "utf8"),
          });
        }
      }
    };
    walk(bundleDir);
    return out;
  }

  async fetchAgentEnvState(envId) {
    const env = this.liveEnvironments.get(envId);
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

  async callLiveAgentTool(envId, toolName, args = {}) {
    const env = this.liveEnvironments.get(envId);
    if (!env) return { ok: false, error: { message: `Unknown live environment: ${envId}` } };

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
    const stateSnapshot = await this.fetchAgentEnvState(envId);
    return {
      ok: !res.isError,
      elapsed_ms: Date.now() - t0,
      tool: toolName,
      result: parsedOutput,
      state_snapshot: stateSnapshot,
    };
  }

  async resetLiveAgentState(envId) {
    const env = this.liveEnvironments.get(envId);
    if (!env) return { ok: false, error: { message: `Unknown live environment: ${envId}` } };

    await fetch(env.rpc_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "data/reset", params: {} }),
    });
    const stateSnapshot = await this.fetchAgentEnvState(envId);
    return { ok: true, state_snapshot: stateSnapshot };
  }

  /**
   * Grade a custom RL task reward verifier against live state AND persist into bundle tasks/.
   */
  async evaluateAndSaveRlTask(envId, taskInput) {
    const env = this.liveEnvironments.get(envId);
    if (!env) return { ok: false, error: { message: `Unknown live environment: ${envId}` } };

    const stateSnapshot = await this.fetchAgentEnvState(envId);
    const collections = this.extractStateCollections(stateSnapshot);

    const assertions = Array.isArray(taskInput.assertions) ? taskInput.assertions : [];
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
      prompt: taskInput.prompt || "Complete the requested operation in the environment.",
      reset_before_run: true,
      verifier: {
        kind: "rea-state-assertions/v1",
        assertions,
      },
      created_at: new Date().toISOString(),
    };

    if (taskInput.save !== false) {
      const tasksDir = join(env.bundle_dir, "tasks");
      mkdirSync(tasksDir, { recursive: true });
      writeFileSync(join(tasksDir, `${taskSlug}.json`), JSON.stringify(taskDocument, null, 2));
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

  listEvidence() {
    return [...this.evidenceLedger.values()]
      .reverse()
      .map(({ evidence, posture, ...meta }) => ({
        ...meta,
        score: posture?.score ?? null,
        grade: posture?.grade ?? null,
      }));
  }

  getEvidenceRecord(evidenceId) {
    return this.evidenceLedger.get(evidenceId) ?? null;
  }

  async close() {
    for (const env of this.liveEnvironments.values()) {
      try {
        await env.envClient.close();
        env.abortController.abort();
        await env.served.close();
      } catch {
        // ignore shutdown errors
      }
    }
    this.liveEnvironments.clear();
    if (this.client) await this.client.close();
    if (this.server) await this.server.close();
    if (this.session) await this.session.close();
    rmSync(this.bundlesDir, { recursive: true, force: true });
  }
}
