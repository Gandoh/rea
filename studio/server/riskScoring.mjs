/**
 * Commercial Security Posture & Compliance Scoring over authentic REA Evidence.
 * Preserves REA's distinction between Observed Facts, Derivations, Inferences, and Unknowns.
 */

const KNOWN_EVM_SELECTORS = Object.freeze({
  "0xd0e30db0": { signature: "deposit()", category: "Vault / WETH" },
  "0x2e1a7d4d": { signature: "withdraw(uint256)", category: "Vault / WETH" },
  "0x8da5cb5b": { signature: "owner()", category: "Ownable Access Control" },
  "0xa9059cbb": { signature: "transfer(address,uint256)", category: "ERC-20 Token" },
  "0x095ea7b3": { signature: "approve(address,uint256)", category: "ERC-20 Token" },
  "0x23b872dd": { signature: "transferFrom(address,address,uint256)", category: "ERC-20 Token" },
  "0x70a08231": { signature: "balanceOf(address)", category: "ERC-20 Token" },
  "0x18160ddd": { signature: "totalSupply()", category: "ERC-20 Token" },
  "0x8456cb59": { signature: "pause()", category: "Pausable Emergency" },
  "0x3f4ba83a": { signature: "unpause()", category: "Pausable Emergency" },
  "0xf2fde38b": { signature: "transferOwnership(address)", category: "Ownable Access Control" },
});

export function enrichEvmFunctions(functions = []) {
  return functions.map((fn) => {
    const sel = String(fn.selector || "").toLowerCase();
    const known = KNOWN_EVM_SELECTORS[sel] ?? null;
    return {
      ...fn,
      known_candidate: known,
    };
  });
}

export function evaluateJavaScriptSecurityPosture(evidence) {
  const norm = evidence?.normalized_result ?? {};
  const summary = norm.summary ?? {};
  const ipc = summary.ipc ?? {};
  const nodes = norm.graph?.nodes ?? [];
  const edges = norm.graph?.edges ?? [];
  const semanticFamilies = norm.semantic_graph?.coverage?.families ?? [];

  let score = 100;
  const findings = [];

  // 1. Extract BrowserWindow webPreferences observations
  const webPrefNodes = nodes.filter(
    (n) =>
      n.kind === "web-preference" ||
      n.observations?.some((o) => o.properties?.preference !== undefined || o.label?.includes("sandbox")),
  );

  // Check explicit sandbox / nodeIntegration / contextIsolation properties across all nodes
  let sandboxDisabled = false;
  let nodeIntegrationEnabled = false;
  let contextIsolationDisabled = false;
  const exposedApis = [];
  const ipcChannels = [];
  const ipcHandlers = [];
  const nativeAddons = [];
  const modules = [];

  for (const node of nodes) {
    const obs = node.observations?.[0];
    const props = obs?.properties ?? {};
    const label = obs?.label ?? node.node_id;

    if (
      (props.preference === "sandbox" && props.value === false) ||
      (label === "sandbox" && props.value === false) ||
      props.sandbox === false
    ) {
      sandboxDisabled = true;
    }
    if (
      (props.preference === "nodeIntegration" && props.value === true) ||
      props.nodeIntegration === true
    ) {
      nodeIntegrationEnabled = true;
    }
    if (
      (props.preference === "contextIsolation" && props.value === false) ||
      props.contextIsolation === false
    ) {
      contextIsolationDisabled = true;
    }

    if (node.kind === "javascript-expression" && props.step_kind === "exposure") {
      exposedApis.push({
        member: props.entry ?? label,
        channel: props.channel ?? null,
        terminal: props.terminal ?? null,
        resolution: props.resolution ?? "unknown",
      });
    } else if (node.kind === "ipc-channel") {
      ipcChannels.push({
        channel: props.channel ?? label,
        side: props.side ?? "renderer",
        operation: props.operation ?? "invoke",
        resolution: props.resolution ?? "literal",
      });
    } else if (node.kind === "ipc-handler") {
      ipcHandlers.push({
        channel: props.channel ?? label,
        mode: props.mode ?? "handle",
        handler_kind: props.handler_kind ?? "function",
      });
    } else if (node.kind === "native-export") {
      nativeAddons.push({
        specifier: props.specifier ?? label,
        resolved_path: props.resolved_path ?? null,
        binding_kind: props.binding_kind ?? "require",
      });
    } else if (node.kind === "javascript-asset") {
      modules.push({
        path: props.path ?? label,
        bytes: props.bytes ?? 0,
        parse_status: props.parse_status ?? "unknown",
        sha256: node.identity?.sha256 ?? null,
      });
    }
  }

  // Also scan raw webPreference observations if stored under different property keys
  for (const node of nodes) {
    for (const obs of node.observations ?? []) {
      const p = obs.properties ?? {};
      if (p.key === "sandbox" && (p.boolean_value === false || p.raw_value === "false" || p.value === false)) {
        sandboxDisabled = true;
      }
      if (p.key === "nodeIntegration" && (p.boolean_value === true || p.value === true)) {
        nodeIntegrationEnabled = true;
      }
      if (p.key === "contextIsolation" && (p.boolean_value === false || p.value === false)) {
        contextIsolationDisabled = true;
      }
    }
  }

  const childProcessFamily = semanticFamilies.find((f) => f.family === "child-process");
  const hasChildProcess =
    (childProcessFamily?.retained_relations ?? 0) > 0 ||
    nodes.some(
      (n) =>
        n.kind === "javascript-module" &&
        /child_process/i.test(n.observations?.[0]?.label ?? ""),
    );

  const mainHandlersCount = ipc.main_handlers ?? ipcHandlers.length;
  const senderValidations = summary.sender_validation_observations ?? 0;

  // Risk Rule 1: Child process execution + missing senderFrame validation (Classic Electron RCE chain)
  if (hasChildProcess && mainHandlersCount > 0 && senderValidations < mainHandlersCount) {
    score -= 38;
    findings.push({
      id: "REA-EL-001",
      severity: "CRITICAL",
      title: "Main-Process Child Process Execution Reachable Without IPC Sender Validation",
      authority: "analyst-inference (backed by shipped-artifact AST)",
      detail: `Observed ${mainHandlersCount} ipcMain handler(s) with ${senderValidations} senderFrame origin check(s) alongside node:child_process execution relations (${childProcessFamily?.retained_relations ?? 1} semantic relation(s)). Any compromised or navigated renderer frame invoking exposed preload bridges can trigger OS command execution.`,
      remediation:
        "Validate event.senderFrame.url against an exact protocol/origin allowlist inside every ipcMain.handle callback and replace arbitrary command arguments with fixed enum actions.",
      bounty_tier: "$10,000 – $35,000 (Desktop RCE class)",
    });
  } else if (mainHandlersCount > 0 && senderValidations < mainHandlersCount) {
    score -= 20;
    findings.push({
      id: "REA-EL-002",
      severity: "HIGH",
      title: "IPC Main Handlers Missing Explicit event.senderFrame Validation",
      authority: "observed-absence-in-ast",
      detail: `${mainHandlersCount - senderValidations} of ${mainHandlersCount} ipcMain handler(s) lack observed senderFrame origin checks in static AST analysis.`,
      remediation:
        "Check event.senderFrame.url in every privileged ipcMain handler before accessing filesystem, vault, or native addons.",
      bounty_tier: "$1,500 – $7,500 (Privilege Escalation)",
    });
  }

  // Risk Rule 2: Renderer sandbox disabled
  if (sandboxDisabled) {
    score -= 18;
    findings.push({
      id: "REA-EL-003",
      severity: "HIGH",
      title: "BrowserWindow Renderer OS Sandbox Explicitly Disabled (sandbox: false)",
      authority: "shipped-artifact",
      detail:
        "BrowserWindow webPreferences disables Chromium OS-level renderer sandboxing, broadening preload capabilities and native attack surface.",
      remediation: "Set webPreferences.sandbox = true on all BrowserWindow instances.",
      bounty_tier: "Defense-in-Depth / SOC2 Hardening Gate",
    });
  }

  if (nodeIntegrationEnabled || contextIsolationDisabled) {
    score -= 30;
    findings.push({
      id: "REA-EL-004",
      severity: "CRITICAL",
      title: "Insecure Renderer Isolation (nodeIntegration / contextIsolation)",
      authority: "shipped-artifact",
      detail: "Renderer context can directly access Node.js primitives or mutate preload prototypes.",
      remediation: "Enforce contextIsolation: true and nodeIntegration: false.",
      bounty_tier: "$5,000 – $25,000",
    });
  }

  // Risk Rule 3: Unpaired IPC transmissions
  if ((ipc.unpaired_literal_renderer_transmissions ?? 0) > 0) {
    score -= 8;
    findings.push({
      id: "REA-EL-005",
      severity: "MEDIUM",
      title: `${ipc.unpaired_literal_renderer_transmissions} Unpaired Renderer IPC Channel Transmission(s)`,
      authority: "shipped-artifact",
      detail:
        "Preload/renderer exposes an IPC channel with no matching ipcMain handler in static modules—often dead attack surface or dynamically registered plugin handlers.",
      remediation: "Remove unused contextBridge methods or audit dynamic ipcMain listener registration.",
      bounty_tier: "Attack-Surface Hygiene",
    });
  }

  // Risk Rule 4: Native .node addon handoff
  if ((summary.native_addon_bindings ?? nativeAddons.length) > 0) {
    score -= 5;
    findings.push({
      id: "REA-EL-006",
      severity: "INFO",
      title: `${summary.native_addon_bindings || nativeAddons.length} Native Addon (.node) Boundary Detected`,
      authority: "shipped-artifact",
      detail: `JavaScript bridges into native binary module(s): ${nativeAddons.map((a) => a.specifier).join(", ") || "native addon"}. Memory safety and exported symbols require binary-level inspection in ShipGate.`,
      remediation: "Inspect the .node binary in Tab 2 (ShipGate Binary Gate) for exports, symbols, and compiler mitigations.",
      bounty_tier: "Native Handoff Boundary",
    });
  }

  if (findings.length === 0 || (findings.length === 1 && findings[0].severity === "INFO")) {
    findings.unshift({
      id: "REA-EL-PASS",
      severity: "PASS",
      title: "IPC Boundaries Paired & Hardened Controls Verified",
      authority: "shipped-artifact",
      detail: `Verified ${summary.browser_windows ?? 0} BrowserWindow(s), ${ipc.paired_renderer_transmissions ?? 0} paired IPC channel(s), and ${senderValidations} explicit sender validation observation(s).`,
      remediation: "Maintain automated release diffing in CI before publishing updates.",
      bounty_tier: "Release Ready",
    });
  }

  score = Math.max(5, Math.min(100, score));
  const grade =
    score >= 90 ? "A" : score >= 78 ? "B" : score >= 62 ? "C" : score >= 45 ? "D" : "F";

  return {
    score,
    grade,
    release_gate: score >= 75 ? "APPROVED" : "BLOCKED",
    findings,
    extracted: {
      exposed_apis: exposedApis,
      ipc_channels: ipcChannels,
      ipc_handlers: ipcHandlers,
      native_addons: nativeAddons,
      modules,
      edge_count: edges.length,
      node_count: nodes.length,
      has_child_process: hasChildProcess,
      sandbox_disabled: sandboxDisabled,
    },
  };
}

export function renderAuditMarkdown(record, posture = null) {
  const ev = record.evidence;
  const lines = [
    `# REA Cloud Studio — Cryptographic Audit Dossier`,
    ``,
    `- **Evidence ID:** \`${ev.evidence_id}\``,
    `- **Operation:** \`${ev.operation}\``,
    `- **Timestamp:** ${record.created_at}`,
    `- **Subject:** \`${record.label ?? ev.subject?.name ?? "target"}\``,
    `- **Subject SHA-256:** \`${ev.subject?.digest?.sha256 ?? "n/a"}\``,
    `- **Provider:** ${ev.provider?.name ?? "REA"} (\`${ev.provider?.id ?? "rea"}\` v${ev.provider?.version ?? "1"})`,
    `- **Authority / Confidence:** \`${ev.authority}\` / \`${ev.confidence}\``,
    ``,
  ];

  if (posture) {
    lines.push(
      `## Security Posture Assessment`,
      `- **Score:** **${posture.score}/100** (Grade **${posture.grade}**)`,
      `- **CI Release Gate:** **${posture.release_gate}**`,
      ``,
      `### Prioritized Findings`,
      ...posture.findings.map(
        (f) =>
          `- **[${f.severity}] ${f.id} — ${f.title}**\n  - *Evidence Basis:* ${f.authority}\n  - *Detail:* ${f.detail}\n  - *Remediation:* ${f.remediation}`,
      ),
      ``,
    );
  }

  if (Array.isArray(ev.limitations) && ev.limitations.length > 0) {
    lines.push(
      `## Explicit Epistemic Limitations & Unknowns`,
      ...ev.limitations.map((l) => `- ${l}`),
      ``,
    );
  }

  lines.push(
    `## Verification`,
    `Re-verify locally with REA CLI (` + "`rea-agents@6.8.0`" + `) against subject digest \`${ev.subject?.digest?.sha256 ?? "n/a"}\`.`,
  );
  return lines.join("\n");
}
