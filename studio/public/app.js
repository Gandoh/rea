function purgeLegacyBrowserSessionTokens() {
  try {
    if (window.localStorage) {
      window.localStorage.removeItem("rea_studio_session");
    }
  } catch {
    // Ignore storage block in restricted iframes
  }
}

purgeLegacyBrowserSessionTokens();

const state = {
  bootstrap: null,
  tenant: null,
  authenticated: false,
  csrfToken: "",
  lastIssuedApiSecret: "",
  activeTab: "xray",
  currentXray: null,
  currentShipgate: null,
  currentRl: null,
  apiKeys: [],
  loadedTabs: new Set(["xray"]),
};

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function shortHash(hash, len = 16) {
  if (!hash) return "n/a";
  return hash.length > len ? `${hash.slice(0, len)}…` : hash;
}

function toast(msg) {
  const wrap = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 3400);
}

function renderTenantTopbar(tenant) {
  state.tenant = tenant || null;
  const planEl = document.getElementById("stat-tenant-plan");
  const quotaEl = document.getElementById("stat-quota");
  const accBtn = document.getElementById("btn-open-account");
  const subEl = document.getElementById("account-modal-sub");

  if (!tenant) {
    if (planEl) planEl.textContent = "Guest";
    if (quotaEl) {
      quotaEl.textContent = "Sign In";
      quotaEl.style.color = "var(--amber)";
    }
    if (accBtn) accBtn.textContent = "Sign In / Sign Up";
    if (subEl) subEl.textContent = "Not signed in — create or sign in to an isolated workspace";
    document.getElementById("stat-sealed").textContent = "0";
    document.getElementById("evidence-count-badge").textContent = "0";
    return;
  }

  if (planEl) planEl.textContent = `${tenant.plan_badge}`;
  if (quotaEl) {
    const used = tenant.usage?.scans_used ?? 0;
    const lim = tenant.usage?.scan_limit;
    quotaEl.textContent = lim === null ? `${used} / ∞` : `${used} / ${lim}`;
    quotaEl.style.color = lim !== null && used >= lim ? "var(--red)" : "var(--cyan)";
  }
  if (accBtn) accBtn.textContent = tenant.org_name;
  if (subEl) subEl.textContent = `Active: ${tenant.org_name} (${tenant.email}) · ${tenant.plan_name}`;
}

function renderUnauthenticatedPrompt(areaId) {
  const area = document.getElementById(areaId);
  if (!area) return;
  area.innerHTML = `
    <div class="card">
      <div class="card-header">
        <h2>Isolated Workspace Authentication Required</h2>
        <span class="pill pill-amber">Tenant-Isolated Security</span>
      </div>
      <p class="muted-sm" style="margin-top:0;">
        Sign in or create a free isolated workspace (5 free monthly scans) to inspect artifacts, retain SHA-256 Evidence envelopes, and launch private AgentEnv sandboxes.
      </p>
      <button class="btn btn-primary btn-sm" type="button" data-open-auth-prompt="1">
        Create Free Workspace or Sign In
      </button>
    </div>
  `;
  area.querySelector("[data-open-auth-prompt]")?.addEventListener("click", () => {
    document.getElementById("account-modal").classList.remove("hidden");
  });
}

function openBillingModal(reasonText = null) {
  const modal = document.getElementById("billing-modal");
  const reasonEl = document.getElementById("billing-modal-reason");
  if (reasonText && reasonEl) reasonEl.textContent = reasonText;
  document.getElementById("sandbox-checkout-slot").innerHTML = "";
  modal.classList.remove("hidden");
}

async function startPlanCheckout(planId) {
  const res = await api("/api/billing/checkout", {
    method: "POST",
    body: JSON.stringify({ plan_id: planId }),
  });
  if (!res.ok) {
    toast(res.error?.message || "Checkout failed");
    return;
  }
  if (res.mode === "live_stripe" && res.checkout_url) {
    window.location.href = res.checkout_url;
    return;
  }

  // Sandbox Checkout Confirmation UI (only returned when ALLOW_SANDBOX_BILLING=true in non-prod)
  const slot = document.getElementById("sandbox-checkout-slot");
  openBillingModal();
  slot.innerHTML = `
    <div class="finding-card finding-INFO" style="margin:6px 0 0;">
      <div class="finding-head">
        <span class="finding-title">Stripe Sandbox Checkout — ${esc(res.plan.name)} ($${res.plan.price_monthly_usd}/mo)</span>
        <span class="pill pill-cyan">Session ${esc(shortHash(res.session_id, 18))}</span>
      </div>
      <div class="finding-detail">
        Explicit local sandbox billing mode is enabled. Confirm below to test plan provisioning.
      </div>
      <button class="btn btn-emerald btn-sm" id="btn-confirm-sandbox-pay" type="button">
        Simulate Successful Stripe Payment &amp; Provision ${esc(res.plan.name)}
      </button>
    </div>
  `;
  document.getElementById("btn-confirm-sandbox-pay").addEventListener("click", async () => {
    const confirmRes = await api("/api/billing/confirm-sandbox", {
      method: "POST",
      body: JSON.stringify({ plan_id: planId }),
    });
    if (confirmRes.ok) {
      renderTenantTopbar(confirmRes.tenant);
      document.getElementById("billing-modal").classList.add("hidden");
      toast(`Upgraded to ${confirmRes.tenant.plan_name}! Quotas unlocked.`);
      if (state.activeTab === "commercial") await loadCommercialTab();
    } else {
      toast(confirmRes.error?.message || "Sandbox provisioning disabled");
    }
  });
}

async function api(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const csrfHeaders =
    method !== "GET" && method !== "HEAD" && state.csrfToken
      ? { "x-csrf-token": state.csrfToken }
      : {};
  const res = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "content-type": "application/json",
      ...csrfHeaders,
      ...(options.headers || {}),
    },
  });
  const data = await res.json();
  if (typeof data?.csrf_token === "string" && data.csrf_token) {
    state.csrfToken = data.csrf_token;
  }
  if (data?.tenant) {
    state.authenticated = true;
    renderTenantTopbar(data.tenant);
  }
  if (res.status === 401 && path !== "/api/auth/login") {
    state.authenticated = false;
    state.csrfToken = "";
    state.tenant = null;
    renderTenantTopbar(null);
    document.getElementById("account-modal")?.classList.remove("hidden");
  } else if (res.status === 402) {
    openBillingModal(data?.error?.message || "Plan quota reached. Upgrade to continue.");
  }
  if (state.authenticated && path !== "/api/evidence" && path !== "/api/bootstrap") {
    await refreshLedgerCounter();
  }
  return data;
}

async function uploadFile(file) {
  if (!state.authenticated) {
    document.getElementById("account-modal")?.classList.remove("hidden");
    throw new Error("Sign in to your workspace before uploading artifacts.");
  }
  const buf = await file.arrayBuffer();
  const res = await fetch("/api/upload", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "content-type": "application/octet-stream",
      "x-filename": file.name,
      ...(state.csrfToken ? { "x-csrf-token": state.csrfToken } : {}),
    },
    body: buf,
  });
  const data = await res.json();
  if (res.status === 401) {
    state.authenticated = false;
    state.csrfToken = "";
    document.getElementById("account-modal")?.classList.remove("hidden");
  }
  if (!data.ok) throw new Error(data.error?.message || "Upload failed");
  return data;
}

async function refreshLedgerCounter() {
  if (!state.authenticated) return;
  try {
    const res = await fetch("/api/evidence", {
      credentials: "same-origin",
    });
    if (!res.ok) return;
    const data = await res.json();
    if (data.ok) {
      if (data.tenant) renderTenantTopbar(data.tenant);
      document.getElementById("stat-sealed").textContent = String(data.records.length);
      document.getElementById("evidence-count-badge").textContent = String(data.records.length);
      if (state.activeTab === "commercial") {
        renderEvidenceTable(data.records);
      }
    }
  } catch {
    // ignore transient poll errors
  }
}

// ============================================================================
// Navigation & Dropzones
// ============================================================================
function setupTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tab = btn.dataset.tab;
      state.activeTab = tab;
      document.querySelectorAll(".tab-btn").forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      document.querySelectorAll(".tab-panel").forEach((p) => {
        p.classList.toggle("active", p.id === `panel-${tab}`);
      });

      if (tab === "commercial" && state.authenticated) {
        await loadCommercialTab();
      } else if (tab === "commercial" && !state.authenticated) {
        renderApiKeys();
        renderEvidenceTable([]);
      }
    });
  });
}

function wireDropzone(zoneId, inputId, btnId, onFileSelected) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  const btn = document.getElementById(btnId);

  btn.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    if (input.files?.[0]) onFileSelected(input.files[0]);
  });

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer?.files?.[0]) onFileSelected(e.dataTransfer.files[0]);
  });
}

// ============================================================================
// TAB 1: Electron / JavaScript X-Ray
// ============================================================================
function renderXraySampleList(selectedId) {
  const list = document.getElementById("xray-samples-list");
  list.innerHTML = (state.bootstrap?.samples?.electron || [])
    .map(
      (s) => `
      <button class="sample-item ${s.id === selectedId ? "selected" : ""}" data-xray-id="${esc(s.id)}">
        <div class="sample-top">
          <span class="sample-name">${esc(s.name)}</span>
          <span class="pill ${s.id.includes("v1") ? "pill-red" : "pill-emerald"}">${esc(s.badge)}</span>
        </div>
        <div class="sample-desc">${esc(s.description)}</div>
      </button>`,
    )
    .join("");

  list.querySelectorAll("[data-xray-id]").forEach((el) => {
    el.addEventListener("click", () => runXraySample(el.dataset.xrayId));
  });
}

async function runXraySample(sampleId) {
  renderXraySampleList(sampleId);
  const area = document.getElementById("xray-results-area");
  area.innerHTML = `<div class="empty-state">Running REA <code>analyze_javascript_application</code> AST &amp; IPC boundary reconstruction…</div>`;
  const res = await api("/api/xray/scan", {
    method: "POST",
    body: JSON.stringify({ sample_id: sampleId }),
  });
  if (!res.ok) {
    area.innerHTML = `<div class="card"><span class="pill pill-red">Error</span> ${esc(res.error?.message || "Scan failed")}</div>`;
    return;
  }
  state.currentXray = res;
  renderXrayResult(res);
}

function renderXrayResult(res) {
  const area = document.getElementById("xray-results-area");
  const p = res.posture;
  const s = res.summary;
  const gradePill =
    p.grade === "A" || p.grade === "B" ? "pill-emerald" : p.grade === "C" ? "pill-amber" : "pill-red";

  area.innerHTML = `
    <div class="card">
      <div class="row-between" style="margin-bottom: 12px;">
        <div>
          <span class="pill ${gradePill}">Posture Grade ${esc(p.grade)} · ${p.score}/100</span>
          <span class="pill ${p.release_gate === "APPROVED" ? "pill-emerald" : "pill-red"}">CI Release Gate: ${esc(p.release_gate)}</span>
          <span class="pill pill-cyan">Completed in ${res.elapsed_ms} ms</span>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" data-open-ev="${esc(res.evidence_id)}">Inspect Evidence (${esc(shortHash(res.evidence_id, 14))})</button>
          <a class="btn btn-sm btn-secondary" href="/api/evidence/${encodeURIComponent(res.evidence_id)}/report?format=md" target="_blank" rel="noopener">Export Audit Dossier (.md)</a>
        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-box">
          <div class="kpi-label">Security Score</div>
          <div class="kpi-val">${p.score}<span style="font-size:13px;color:var(--text-2)">/100</span></div>
          <div class="kpi-sub">Root SHA-256: <code>${esc(shortHash(res.root_artifact_sha256, 12))}</code></div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">ContextBridge APIs</div>
          <div class="kpi-val">${s.exposed_api_members}</div>
          <div class="kpi-sub">${s.browser_windows} BrowserWindow · ${s.preload_entrypoints} preload</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">IPC Channels</div>
          <div class="kpi-val">${s.ipc.paired_renderer_transmissions} <span style="font-size:13px;color:var(--text-2)">paired</span></div>
          <div class="kpi-sub">${s.ipc.main_handlers} ipcMain · ${s.ipc.unpaired_literal_renderer_transmissions} unpaired</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Sender Origin Checks</div>
          <div class="kpi-val" style="color:${s.sender_validation_observations > 0 ? "var(--emerald)" : "var(--amber)"}">${s.sender_validation_observations}</div>
          <div class="kpi-sub">${s.native_addon_bindings} native .node binding(s)</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>Prioritized Security &amp; Architecture Findings</h2>
        <span class="muted-sm">Derived from REA Application &amp; Semantic Graphs</span>
      </div>
      ${p.findings
        .map(
          (f) => `
        <div class="finding-card finding-${esc(f.severity)}">
          <div class="finding-head">
            <span class="finding-title">[${esc(f.severity)}] ${esc(f.id)} — ${esc(f.title)}</span>
            <span class="pill pill-violet">${esc(f.bounty_tier)}</span>
          </div>
          <div class="finding-detail">${esc(f.detail)}</div>
          <div class="finding-rem"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
        </div>`,
        )
        .join("")}
    </div>

    <div class="rl-two-col">
      <div class="card">
        <div class="card-header">
          <h2>Exposed Preload Bridge &amp; IPC Map</h2>
          <span class="muted-sm">Click any channel to trace</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Exposed Member / Handler</th>
              <th>IPC Channel</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${
              p.extracted.exposed_apis.length === 0 && p.extracted.ipc_handlers.length === 0
                ? `<tr><td colspan="3" class="muted-sm">No Electron IPC channels observed in target.</td></tr>`
                : [
                    ...p.extracted.exposed_apis.map(
                      (a) => `
                  <tr>
                    <td class="mono">${esc(a.member)}</td>
                    <td><code>${esc(a.channel || "—")}</code></td>
                    <td>
                      ${
                        a.channel
                          ? `<button class="btn btn-sm btn-outline" data-quick-trace-kind="channel" data-quick-trace-val="${esc(a.channel)}">Trace</button>`
                          : ""
                      }
                    </td>
                  </tr>`,
                    ),
                    ...p.extracted.ipc_handlers.map(
                      (h) => `
                  <tr>
                    <td class="mono">ipcMain.${esc(h.mode)}</td>
                    <td><code>${esc(h.channel)}</code></td>
                    <td><button class="btn btn-sm btn-outline" data-quick-trace-kind="channel" data-quick-trace-val="${esc(h.channel)}">Trace</button></td>
                  </tr>`,
                    ),
                  ].join("")
            }
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Inventoried JS Modules &amp; Semantic Coverage</h2>
          <span class="pill pill-cyan">${res.statistics.visited_ast_nodes} AST nodes</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Module</th>
              <th>Bytes</th>
              <th>SHA-256</th>
              <th>Trace</th>
            </tr>
          </thead>
          <tbody>
            ${p.extracted.modules
              .map(
                (m) => `
              <tr>
                <td class="mono">${esc(m.path)}</td>
                <td class="mono">${m.bytes} B</td>
                <td class="mono muted-sm">${esc(shortHash(m.sha256, 12))}</td>
                <td><button class="btn btn-sm btn-outline" data-quick-trace-kind="module" data-quick-trace-val="${esc(m.path)}">Trace</button></td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
    </div>

    <div id="xray-subpanel"></div>
  `;

  area.querySelectorAll("[data-open-ev]").forEach((btn) => {
    btn.addEventListener("click", () => openEvidenceModal(btn.dataset.openEv));
  });

  area.querySelectorAll("[data-quick-trace-val]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("trace-seed-kind").value = btn.dataset.quickTraceKind;
      document.getElementById("trace-seed-value").value = btn.dataset.quickTraceVal;
      runFeatureTrace();
    });
  });
}

async function runFeatureTrace() {
  if (!state.currentXray?.evidence_id) {
    toast("Scan a JavaScript/Electron target first.");
    return;
  }
  const kind = document.getElementById("trace-seed-kind").value;
  const val = document.getElementById("trace-seed-value").value.trim();
  const dir = document.getElementById("trace-direction").value;
  if (!val) return;

  const slot = document.getElementById("xray-subpanel");
  slot.innerHTML = `<div class="card">Tracing <code>${esc(kind)} = ${esc(val)}</code> across retained Evidence…</div>`;

  const res = await api("/api/xray/trace", {
    method: "POST",
    body: JSON.stringify({
      evidence_id: state.currentXray.evidence_id,
      seed_kind: kind,
      seed_value: val,
      direction: dir,
      match: "contains",
    }),
  });

  if (!res.ok) {
    slot.innerHTML = `<div class="card"><span class="pill pill-red">Trace Failed</span> ${esc(res.error?.message || "Invalid seed")}</div>`;
    return;
  }

  const nodes = res.trace?.subgraph?.nodes ?? res.trace?.matched_nodes ?? [];
  const edges = res.trace?.subgraph?.edges ?? [];
  slot.innerHTML = `
    <div class="card">
      <div class="card-header">
        <h2>Feature Trace Result: <code>${esc(kind)}:${esc(val)}</code></h2>
        <div class="btn-group">
          <span class="pill pill-emerald">${nodes.length} Reachable Nodes · ${edges.length} Edges (${res.elapsed_ms} ms)</span>
          <button class="btn btn-sm btn-outline" data-open-ev="${esc(res.evidence_id)}">Inspect Trace Evidence</button>
        </div>
      </div>
      <pre class="code-block mono">${esc(JSON.stringify(res.trace, null, 2).slice(0, 5000))}</pre>
    </div>
  `;
  slot.querySelector("[data-open-ev]")?.addEventListener("click", (e) => {
    openEvidenceModal(e.currentTarget.dataset.openEv);
  });
}

async function runVersionComparison() {
  const area = document.getElementById("xray-results-area");
  area.innerHTML = `<div class="empty-state">Running REA <code>compare_application_versions</code> between Acme v1.4.0 and Hardened v2.0.0…</div>`;
  const res = await api("/api/xray/compare", {
    method: "POST",
    body: JSON.stringify({ left: "acme-desktop-v1", right: "acme-desktop-v2" }),
  });
  if (!res.ok) {
    toast("Comparison failed");
    return;
  }
  const sum = res.comparison?.summary ?? {};
  area.innerHTML = `
    <div class="card">
      <div class="card-header">
        <h2>CI/CD Release Gate Diff: Acme v1.4.0 → Hardened v2.0.0</h2>
        <button class="btn btn-sm btn-outline" data-open-ev="${esc(res.evidence_id)}">Inspect Diff Evidence (${esc(shortHash(res.evidence_id, 14))})</button>
      </div>
      <div class="kpi-grid" style="margin-bottom:14px;">
        <div class="kpi-box">
          <div class="kpi-label">Posture Shift</div>
          <div class="kpi-val" style="color:var(--emerald)">Grade ${esc(res.left_posture?.grade)} (${res.left_posture?.score}) → ${esc(res.right_posture?.grade)} (${res.right_posture?.score})</div>
          <div class="kpi-sub">Gate: ${esc(res.left_posture?.release_gate)} → ${esc(res.right_posture?.release_gate)}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Added Entities</div>
          <div class="kpi-val">+${sum.added ?? 0}</div>
          <div class="kpi-sub">senderFrame checks &amp; key-rotation IPC</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Removed Surface</div>
          <div class="kpi-val" style="color:var(--cyan)">-${sum.removed ?? 0}</div>
          <div class="kpi-sub">Removed child_process shell IPC</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Modified / Unknown</div>
          <div class="kpi-val">${sum.changed ?? 0} / ${sum.unknown ?? 0}</div>
          <div class="kpi-sub">Explicit epistemic frontier preserved</div>
        </div>
      </div>
      <pre class="code-block mono">${esc(JSON.stringify(res.comparison, null, 2).slice(0, 6000))}</pre>
    </div>
  `;
  area.querySelector("[data-open-ev]")?.addEventListener("click", (e) => {
    openEvidenceModal(e.currentTarget.dataset.openEv);
  });
}

// ============================================================================
// TAB 2: ShipGate — Binary, AI Model, EVM & Bytecode Gate
// ============================================================================
function renderShipgateSampleList(selectedId) {
  const list = document.getElementById("shipgate-samples-list");
  list.innerHTML = (state.bootstrap?.samples?.binary || [])
    .map(
      (s) => `
      <button class="sample-item ${s.id === selectedId ? "selected" : ""}" data-sg-id="${esc(s.id)}">
        <div class="sample-top">
          <span class="sample-name">${esc(s.name)}</span>
          <span class="pill pill-emerald">${esc(s.badge)}</span>
        </div>
        <div class="sample-desc">${esc(s.description)}</div>
      </button>`,
    )
    .join("");

  list.querySelectorAll("[data-sg-id]").forEach((el) => {
    el.addEventListener("click", () => runShipGateSample(el.dataset.sgId));
  });
}

async function runShipGateSample(sampleId, symbol = null) {
  renderShipgateSampleList(sampleId);
  const area = document.getElementById("shipgate-results-area");
  area.innerHTML = `<div class="empty-state">Running REA static binary/model/bytecode inspectors…</div>`;
  const res = await api("/api/shipgate/inspect", {
    method: "POST",
    body: JSON.stringify({ sample_id: sampleId, symbol }),
  });
  if (!res.ok) {
    area.innerHTML = `<div class="card"><span class="pill pill-red">Error</span> ${esc(res.error?.message || "Inspection failed")}</div>`;
    return;
  }
  res._sampleId = sampleId;
  state.currentShipgate = res;
  renderShipGateResult(res);
}

function renderEntropyChart(entropyPanel) {
  if (!entropyPanel) return "";
  const blocks = entropyPanel.blocks ?? [];
  const overall = Number(
    entropyPanel.file_entropy ?? entropyPanel.overall_entropy ?? entropyPanel.entropy ?? 0,
  );
  const bars = blocks.slice(0, 64);
  const barWidth = bars.length > 0 ? Math.max(6, Math.floor(640 / bars.length) - 2) : 12;

  const svgBars = bars
    .map((b, i) => {
      const val = Number(b.entropy ?? 0);
      const h = Math.max(3, Math.round((val / 8) * 68));
      const y = 72 - h;
      const color = val > 7.2 ? "#ef4444" : val > 5.5 ? "#f59e0b" : "#38bdf8";
      return `<rect x="${i * (barWidth + 2)}" y="${y}" width="${barWidth}" height="${h}" rx="2" fill="${color}">
        <title>Offset ${b.offset}: ${val.toFixed(3)} bits/byte</title>
      </rect>`;
    })
    .join("");

  return `
    <div class="card">
      <div class="card-header">
        <h2>Shannon Byte Entropy Profile (<code>inspect_byte_entropy</code>)</h2>
        <span class="pill ${overall > 7.2 ? "pill-red" : "pill-cyan"}">Overall: ${overall.toFixed(3)} / 8.000 bits/byte</span>
      </div>
      <div class="entropy-wrap">
        <svg viewBox="0 0 ${Math.max(300, bars.length * (barWidth + 2))} 76" width="100%" height="78" preserveAspectRatio="none">
          ${svgBars}
        </svg>
        <div class="row-between muted-sm" style="margin-top:6px;">
          <span>${blocks.length} block(s) examined · Low (&lt;5.5 structured code/headers)</span>
          <span>High (&gt;7.2 compressed/encrypted/packed payload)</span>
        </div>
      </div>
    </div>
  `;
}

function renderShipGateResult(res) {
  const area = document.getElementById("shipgate-results-area");
  const art = res.artifact;
  const p = res.panels;

  let specializedHtml = "";

  // 1. ELF Binary + Exports + Disassembly
  if (p.exports || p.disassembly) {
    const exportsList = p.exports?.exports ?? [];
    specializedHtml += `
      <div class="card">
        <div class="card-header">
          <h2>Dynamic ELF Symbol Exports (<code>inspect_native_exports</code>)</h2>
          <span class="pill pill-emerald">${exportsList.length} Exported Function(s) · ${esc(p.exports?.architecture || "x64")}</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Symbol Name</th>
              <th>Virtual Address</th>
              <th>Size</th>
              <th>Binding</th>
              <th>Disassemble</th>
            </tr>
          </thead>
          <tbody>
            ${exportsList
              .map(
                (ex) => `
              <tr>
                <td class="mono"><strong>${esc(ex.name)}</strong></td>
                <td class="mono">${esc(ex.value)}</td>
                <td class="mono">${esc(ex.size)} B</td>
                <td><span class="pill pill-cyan">${esc(ex.binding)}</span></td>
                <td><button class="btn btn-sm btn-outline" data-disasm-sym="${esc(ex.name)}">Disassemble Symbol</button></td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
      ${
        p.disassembly
          ? `
      <div class="card">
        <div class="card-header">
          <h2>GNU objdump x86-64 Disassembly ${p.disassembly.symbol ? `(Symbol: <code>${esc(p.disassembly.symbol)}</code>)` : "(All Code Sections)"}</h2>
          ${p.disassembly.symbol ? `<button class="btn btn-sm btn-outline" id="btn-disasm-all">Show Full Disassembly</button>` : ""}
        </div>
        <pre class="code-block mono">${esc(p.disassembly.stdout)}</pre>
      </div>`
          : ""
      }
    `;
  }

  // 2. AI Model (Safetensors / GGUF)
  if (p.model) {
    const sum = p.model.summary;
    const tensors = p.model.tensors || [];
    const metadata = p.model.metadata || [];
    specializedHtml += `
      <div class="card">
        <div class="card-header">
          <h2>AI Model Supply-Chain Attestation (<code>inspect_model_artifact</code>)</h2>
          <span class="pill pill-emerald">Format: ${esc(sum.format)} · ${esc(sum.totals?.parameter_count)} Parameters</span>
        </div>
        <div class="kpi-grid" style="margin-bottom:14px;">
          <div class="kpi-box">
            <div class="kpi-label">Declared Tensors</div>
            <div class="kpi-val">${sum.counts?.tensors ?? tensors.length}</div>
            <div class="kpi-sub">Storage: ${esc(sum.coverage?.storage_sizes)}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-label">Tensor Payload Bytes</div>
            <div class="kpi-val">${sum.totals?.tensor_bytes ?? 0} B</div>
            <div class="kpi-sub">Data offset: ${sum.tensor_data_offset}</div>
          </div>
          <div class="kpi-box">
            <div class="kpi-label">Header SHA-256</div>
            <div class="kpi-val" style="font-size:14px;">${esc(shortHash(sum.artifact?.header_sha256, 16))}</div>
            <div class="kpi-sub">Weights never executed</div>
          </div>
        </div>

        <h3 style="margin:10px 0 6px;font-size:13px;">Model Metadata Declarations</h3>
        <div class="btn-group" style="margin-bottom:14px;">
          ${metadata.map((m) => `<span class="pill pill-violet">${esc(m.key)}: ${esc(m.value)}</span>`).join("")}
        </div>

        <h3 style="margin:10px 0 6px;font-size:13px;">Verified Tensor Layout</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>Tensor Name</th>
              <th>DType</th>
              <th>Shape</th>
              <th>File Offset</th>
              <th>Bytes</th>
              <th>Validation</th>
            </tr>
          </thead>
          <tbody>
            ${tensors
              .map(
                (t) => `
              <tr>
                <td class="mono">${esc(t.name)}</td>
                <td><span class="pill pill-cyan">${esc(t.type)}</span></td>
                <td class="mono">[${esc((t.shape || []).join(" × "))}]</td>
                <td class="mono">${t.file_offset}</td>
                <td class="mono">${t.byte_length} B</td>
                <td><span class="pill pill-emerald">${esc(t.storage_validation)}</span></td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  // 3. EVM Unverified Smart Contract Bytecode
  if (p.evm) {
    const fns = p.evm.functions || [];
    specializedHtml += `
      <div class="card">
        <div class="card-header">
          <h2>Offline EVM Bytecode Interface Recovery (<code>inspect_evm_interface</code>)</h2>
          <span class="pill pill-violet">${fns.length} Dispatch Selector(s) Inferred · Zero RPC Calls</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>4-Byte Selector</th>
              <th>Reference Signature Candidate</th>
              <th>Dispatch Offset</th>
              <th>Inferred Args (EVMole)</th>
              <th>Inferred Mutability</th>
            </tr>
          </thead>
          <tbody>
            ${fns
              .map(
                (fn) => `
              <tr>
                <td class="mono"><strong>${esc(fn.selector)}</strong></td>
                <td>
                  ${
                    fn.known_candidate
                      ? `<code style="color:var(--cyan)">${esc(fn.known_candidate.signature)}</code> <span class="muted-sm">(${esc(fn.known_candidate.category)})</span>`
                      : `<span class="muted-sm">Unindexed custom selector</span>`
                  }
                </td>
                <td class="mono">0x${Number(fn.bytecode_offset).toString(16)} (${fn.bytecode_offset})</td>
                <td class="mono">${esc(fn.inferred_arguments || "()")}</td>
                <td><span class="pill ${fn.inferred_state_mutability === "payable" ? "pill-amber" : "pill-emerald"}">${esc(fn.inferred_state_mutability)}</span></td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  // 4. Python .pyc Marshal Inspection
  if (p.python_pyc) {
    const pyc = p.python_pyc;
    specializedHtml += `
      <div class="card">
        <div class="card-header">
          <h2>CPython Compiled Bytecode Forensics (<code>inspect_python_pyc</code>)</h2>
          <span class="pill pill-cyan">Python ${esc(pyc.header?.python_version)} · Magic ${pyc.header?.magic}</span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Code Object</th>
              <th>Args / Stack</th>
              <th>Locals &amp; Names</th>
              <th>Embedded Constants</th>
              <th>Bytecode SHA-256</th>
            </tr>
          </thead>
          <tbody>
            ${(pyc.code_objects || [])
              .map(
                (co) => `
              <tr>
                <td class="mono"><strong>${esc(co.qualname || co.name)}</strong></td>
                <td class="mono">args=${co.argcount}, stack=${co.stacksize}</td>
                <td class="mono muted-sm">${esc([...(co.localsplusnames || []), ...(co.names || [])].join(", ") || "—")}</td>
                <td class="mono">${esc(
                  (co.consts || [])
                    .filter((c) => c.kind !== "none")
                    .map((c) => `${c.kind}:${c.value ?? c.name ?? ""}`)
                    .join(", ") || "—",
                )}</td>
                <td class="mono muted-sm">${esc(shortHash(co.bytecode?.sha256, 14))}</td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  // Fallback raw panels for PE / APK / BEAM / generic uploads
  for (const extraKey of ["pe_imports", "pe_certificates", "pe_load_config", "apk_signature", "go_metadata", "rust_crates", "erlang_beam"]) {
    if (p[extraKey]) {
      specializedHtml += `
        <div class="card">
          <div class="card-header"><h2>${esc(extraKey.replaceAll("_", " ").toUpperCase())}</h2></div>
          <pre class="code-block mono">${esc(JSON.stringify(p[extraKey], null, 2).slice(0, 5000))}</pre>
        </div>
      `;
    }
  }

  area.innerHTML = `
    <div class="card">
      <div class="row-between">
        <div>
          <span class="pill pill-emerald">Target: ${esc(art.name)}</span>
          <span class="pill pill-cyan">Format: ${esc(art.detected_kind)} · ${art.bytes} bytes</span>
          <span class="pill pill-violet">${res.elapsed_ms} ms</span>
        </div>
        <div class="btn-group">
          ${(res.evidence_ids || [])
            .slice(0, 3)
            .map(
              (id) =>
                `<button class="btn btn-sm btn-outline" data-open-ev="${esc(id)}">${esc(shortHash(id, 13))}</button>`,
            )
            .join("")}
        </div>
      </div>
      <div class="muted-sm mono" style="margin-top:8px;">Artifact SHA-256: ${esc(art.sha256)}</div>
    </div>
    ${specializedHtml}
    ${renderEntropyChart(p.entropy)}
  `;

  area.querySelectorAll("[data-open-ev]").forEach((btn) => {
    btn.addEventListener("click", () => openEvidenceModal(btn.dataset.openEv));
  });

  area.querySelectorAll("[data-disasm-sym]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (res._sampleId) runShipGateSample(res._sampleId, btn.dataset.disasmSym);
    });
  });

  area.querySelector("#btn-disasm-all")?.addEventListener("click", () => {
    if (res._sampleId) runShipGateSample(res._sampleId, null);
  });
}

// ============================================================================
// TAB 3: RL Factory — HAR-to-AgentEnv Builder & Live Sandbox
// ============================================================================
function renderRlSampleList(selectedId) {
  const list = document.getElementById("rl-samples-list");
  list.innerHTML = (state.bootstrap?.samples?.har || [])
    .map(
      (s) => `
      <button class="sample-item ${s.id === selectedId ? "selected" : ""}" data-har-id="${esc(s.id)}">
        <div class="sample-top">
          <span class="sample-name">${esc(s.name)}</span>
          <span class="pill pill-violet">${esc(s.badge)}</span>
        </div>
        <div class="sample-desc">${esc(s.description)}</div>
      </button>`,
    )
    .join("");

  list.querySelectorAll("[data-har-id]").forEach((el) => {
    el.addEventListener("click", () => runRlSample(el.dataset.harId));
  });
}

async function runRlSample(sampleId) {
  renderRlSampleList(sampleId);
  const area = document.getElementById("rl-results-area");
  area.innerHTML = `<div class="empty-state">Running REA <code>inspect_web_network_capture</code> → <code>export_environment_bundle</code> → launching live <code>serveEnvironment</code> MCP sandbox…</div>`;
  const res = await api("/api/rl/build", {
    method: "POST",
    body: JSON.stringify({ sample_id: sampleId }),
  });
  if (!res.ok) {
    area.innerHTML = `<div class="card"><span class="pill pill-red">Build Error</span> ${esc(res.error?.message || "Failed to build AgentEnv")}</div>`;
    return;
  }
  state.currentRl = res;
  renderRlStudio(res);
}

function defaultArgsForTool(tool) {
  const props = tool?.inputSchema?.properties ?? {};
  const sample = {};
  for (const [k, schema] of Object.entries(props)) {
    if (k === "body") {
      if (tool.name.includes("ticket")) {
        sample.body = tool.name.startsWith("patch")
          ? { status: "resolved" }
          : { title: "Replica failover alert", priority: "high" };
      } else if (tool.name.includes("payout")) {
        sample.body = tool.name.startsWith("patch")
          ? { state: "approved" }
          : { recipient: "VectorCompute Inc", amount_usd: 8900 };
      } else {
        sample.body = {};
      }
    } else if (/id$/i.test(k)) {
      sample[k] = tool.name.includes("payout") ? "p1" : "t1";
    } else if (schema.type === "string") {
      sample[k] = "";
    }
  }
  return sample;
}

function renderRlStudio(res) {
  const area = document.getElementById("rl-results-area");
  const dlSlot = document.getElementById("rl-download-slot");
  const rep = res.report;
  const cov = rep.coverage || { reads: { state: 0, recorded: 0 }, writes: { served: [], withheld: [] } };

  dlSlot.innerHTML = `
    <a class="btn btn-emerald" href="/api/rl/download/${encodeURIComponent(res.env_id)}">
      Download Runnable AgentEnv Bundle (.zip)
    </a>
  `;

  const defaultCollection = res.name.includes("fintech") ? "/api/payouts" : "/api/tickets";
  const defaultField = res.name.includes("fintech") ? "recipient" : "title";
  const defaultExpected = res.name.includes("fintech") ? "VectorCompute Inc" : "Replica failover alert";

  area.innerHTML = `
    <div class="card">
      <div class="row-between" style="margin-bottom:12px;">
        <div>
          <span class="pill pill-emerald">Live AgentEnv Running: ${esc(res.name)}</span>
          <span class="pill pill-violet">${res.tools.length} Callable MCP Tools</span>
          <span class="pill pill-cyan">State Engine: ${rep.state?.served ? "Synthesized CRUD State" : "Recorded Replay"} (${res.elapsed_ms} ms)</span>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" data-open-ev="${esc(rep.capture?.evidence_id)}">Capture Evidence</button>
          <button class="btn btn-sm btn-outline" data-open-ev="${esc(rep.manifest?.evidence_id)}">Manifest Evidence</button>
        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-box">
          <div class="kpi-label">HTTP Records Parsed</div>
          <div class="kpi-val">${rep.capture?.records ?? 0}</div>
          <div class="kpi-sub">HAR 1.2 Offline Capture</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Stateful Read Tools</div>
          <div class="kpi-val" style="color:var(--emerald)">${cov.reads?.state ?? 0}</div>
          <div class="kpi-sub">${cov.reads?.recorded ?? 0} replay-only fallback</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Confirmed CRUD Writes</div>
          <div class="kpi-val" style="color:var(--cyan)">${cov.writes?.served?.length ?? 0}</div>
          <div class="kpi-sub">${(cov.writes?.served || []).map((w) => `${esc(w.tool)} (${esc(w.effect)})`).join(", ") || "none"}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Withheld Unconfirmed Writes</div>
          <div class="kpi-val" style="color:var(--amber)">${cov.writes?.withheld?.length ?? 0}</div>
          <div class="kpi-sub">Safety-gated by REA</div>
        </div>
      </div>

      ${
        (cov.writes?.withheld || []).length > 0
          ? `<div style="margin-top:12px;">
              ${cov.writes.withheld
                .map(
                  (w) => `
                <div class="finding-card finding-HIGH" style="margin-bottom:0;">
                  <div class="finding-head">
                    <span class="finding-title">Withheld Write Tool: <code>${esc(w.tool)}</code> (Reason: <code>${esc(w.reason)}</code>)</span>
                    <span class="pill pill-amber">Recording Guidance</span>
                  </div>
                  <div class="finding-detail">${esc(w.hint)}</div>
                </div>`,
                )
                .join("")}
            </div>`
          : ""
      }
    </div>

    <div class="rl-two-col">
      <!-- Left: Interactive Agent Tool Caller -->
      <div class="card">
        <div class="card-header">
          <h2>Live AgentEnv Tool Playground</h2>
          <button class="btn btn-sm btn-outline" id="btn-rl-reset">Reset State (data/reset)</button>
        </div>
        <p class="muted-sm">Execute synthesized MCP tools against the live environment server and watch backing state mutate.</p>
        <div class="stack-sm">
          <div>
            <label class="field-label">Select Synthesized MCP Tool</label>
            <select id="rl-tool-select" class="input mono">
              ${res.tools.map((t) => `<option value="${esc(t.name)}">${esc(t.name)} — ${esc((t.description || "").slice(0, 62))}</option>`).join("")}
            </select>
          </div>
          <div>
            <label class="field-label">Tool Arguments (JSON)</label>
            <textarea id="rl-tool-args" class="input mono" rows="4"></textarea>
          </div>
          <button class="btn btn-primary" id="btn-rl-exec">Execute Tool Against Live AgentEnv</button>
          <div>
            <label class="field-label">Tool Response</label>
            <pre class="code-block mono" id="rl-tool-output">Select a tool (e.g. post_* to create an item, then get_* to verify state) and click Execute.</pre>
          </div>
        </div>
      </div>

      <!-- Right: Live State Inspector & RL Task Grader -->
      <div class="card">
        <div class="card-header">
          <h2>Live <code>rea-state/v1</code> Snapshot &amp; Reward Verifier</h2>
          <span class="pill pill-emerald">JSON-RPC /agentenv</span>
        </div>
        <pre class="code-block mono" id="rl-state-box" style="max-height:190px;">${esc(JSON.stringify(res.state_snapshot, null, 2))}</pre>

        <div class="divider"></div>
        <h3 style="margin:0 0 8px;font-size:13.5px;">Author RL Task &amp; Run Live Reward Check</h3>
        <div class="stack-sm">
          <div>
            <label class="field-label">Agent Task Prompt</label>
            <input id="rl-task-prompt" class="input" value="Create a new record '${esc(defaultExpected)}' so it persists in ${esc(defaultCollection)}." />
          </div>
          <div class="row-2">
            <div>
              <label class="field-label">State Collection</label>
              <input id="rl-assert-col" class="input mono" value="${esc(defaultCollection)}" />
            </div>
            <div>
              <label class="field-label">Field Equals</label>
              <input id="rl-assert-kv" class="input mono" value="${esc(`${defaultField}=${defaultExpected}`)}" />
            </div>
          </div>
          <button class="btn btn-secondary" id="btn-rl-grade">Evaluate Reward Verifier &amp; Save to Bundle</button>
          <div id="rl-grade-result"></div>
        </div>
      </div>
    </div>

    <!-- Exported Bundle File Explorer -->
    <div class="card">
      <div class="card-header">
        <h2>Generated Runnable AgentEnv Bundle Files (<code>agent-env run ./${esc(res.name)}</code>)</h2>
        <select id="rl-file-select" class="input mono" style="width:auto;min-width:280px;">
          ${res.bundle_files.map((f, i) => `<option value="${i}">${esc(f.path)} (${f.bytes} B)</option>`).join("")}
        </select>
      </div>
      <pre class="code-block mono" id="rl-file-preview">${esc(res.bundle_files[0]?.preview || "")}</pre>
    </div>
  `;

  area.querySelectorAll("[data-open-ev]").forEach((btn) => {
    btn.addEventListener("click", () => openEvidenceModal(btn.dataset.openEv));
  });

  const toolSelect = document.getElementById("rl-tool-select");
  const argsBox = document.getElementById("rl-tool-args");
  const syncDefaultArgs = () => {
    const chosen = res.tools.find((t) => t.name === toolSelect.value);
    argsBox.value = JSON.stringify(defaultArgsForTool(chosen), null, 2);
  };
  // Pre-select POST create tool by default so 1 click demonstrates state mutation!
  const postTool = res.tools.find((t) => t.name.startsWith("post_"));
  if (postTool) toolSelect.value = postTool.name;
  syncDefaultArgs();
  toolSelect.addEventListener("change", syncDefaultArgs);

  document.getElementById("btn-rl-exec").addEventListener("click", async () => {
    let parsedArgs = {};
    try {
      parsedArgs = JSON.parse(argsBox.value || "{}");
    } catch {
      toast("Invalid JSON in Tool Arguments");
      return;
    }
    const callRes = await api("/api/rl/call", {
      method: "POST",
      body: JSON.stringify({
        env_id: res.env_id,
        tool: toolSelect.value,
        arguments: parsedArgs,
      }),
    });
    document.getElementById("rl-tool-output").textContent = JSON.stringify(callRes.result, null, 2);
    document.getElementById("rl-state-box").textContent = JSON.stringify(callRes.state_snapshot, null, 2);
    toast(`Executed ${toolSelect.value} (${callRes.elapsed_ms} ms)`);
  });

  document.getElementById("btn-rl-reset").addEventListener("click", async () => {
    const resetRes = await api("/api/rl/reset", {
      method: "POST",
      body: JSON.stringify({ env_id: res.env_id }),
    });
    document.getElementById("rl-state-box").textContent = JSON.stringify(resetRes.state_snapshot, null, 2);
    toast("Environment state reset to initial capture baseline");
  });

  document.getElementById("btn-rl-grade").addEventListener("click", async () => {
    const prompt = document.getElementById("rl-task-prompt").value;
    const collection = document.getElementById("rl-assert-col").value.trim();
    const kv = document.getElementById("rl-assert-kv").value.trim();
    const eqIdx = kv.indexOf("=");
    const field = eqIdx >= 0 ? kv.slice(0, eqIdx).trim() : "title";
    const expected = eqIdx >= 0 ? kv.slice(eqIdx + 1).trim() : kv;

    const gradeRes = await api("/api/rl/grade-task", {
      method: "POST",
      body: JSON.stringify({
        env_id: res.env_id,
        task: {
          title: `verify-${field}`,
          prompt,
          assertions: [{ collection, field, operator: "equals", expected }],
        },
      }),
    });
    if (gradeRes.ok) {
      res.bundle_files = gradeRes.bundle_files;
      const fileSelect = document.getElementById("rl-file-select");
      fileSelect.innerHTML = res.bundle_files
        .map((f, i) => `<option value="${i}">${esc(f.path)} (${f.bytes} B)</option>`)
        .join("");

      document.getElementById("rl-grade-result").innerHTML = `
        <div class="finding-card ${gradeRes.passed ? "finding-PASS" : "finding-HIGH"}" style="margin:6px 0 0;">
          <div class="finding-head">
            <span class="finding-title">Reward Score: <code>${gradeRes.reward.toFixed(1)}</code> (${gradeRes.passed ? "TASK PASSED" : "NOT YET SATISFIED — Run POST tool on the left!"})</span>
            <span class="pill pill-violet">Saved to tasks/${esc(gradeRes.task.id)}.json</span>
          </div>
        </div>
      `;
    }
  });

  document.getElementById("rl-file-select").addEventListener("change", (e) => {
    const file = res.bundle_files[Number(e.target.value)];
    document.getElementById("rl-file-preview").textContent = file?.preview || "";
  });
}

// ============================================================================
// TAB 4: Evidence Vault, Pricing Simulator & B2B API Console
// ============================================================================
function setupRevenueSimulator() {
  const update = () => {
    const c1 = Number(document.getElementById("sim-c1").value);
    const c2 = Number(document.getElementById("sim-c2").value);
    const c3 = Number(document.getElementById("sim-c3").value);
    document.getElementById("sim-c1-val").textContent = String(c1);
    document.getElementById("sim-c2-val").textContent = String(c2);
    document.getElementById("sim-c3-val").textContent = String(c3);

    const mrr = c1 * 49 + c2 * 299 + c3 * 1499;
    const arr = mrr * 12;
    document.getElementById("sim-mrr").textContent = `$${mrr.toLocaleString()} / mo`;
    document.getElementById("sim-arr").textContent = `$${arr.toLocaleString()} / yr`;
  };
  ["sim-c1", "sim-c2", "sim-c3"].forEach((id) => {
    document.getElementById(id).addEventListener("input", update);
  });
  update();
}

async function loadCommercialTab() {
  if (!state.authenticated) {
    renderApiKeys();
    renderEvidenceTable([]);
    return;
  }
  const boot = await api("/api/bootstrap");
  if (boot.ok) {
    state.apiKeys = boot.api_keys || [];
    renderApiKeys();
  }
  const ev = await api("/api/evidence");
  if (ev.ok) renderEvidenceTable(ev.records);
}

function renderOneTimeKeyBanner() {
  const slot = document.getElementById("one-time-key-banner");
  if (!slot) return;
  if (!state.lastIssuedApiSecret) {
    slot.innerHTML = "";
    return;
  }
  slot.innerHTML = `
    <div class="finding-card finding-PASS" style="margin-bottom:10px;">
      <div class="finding-head">
        <span class="finding-title">Copy Your Secret API Key Now (Shown Once Only)</span>
        <span class="pill pill-emerald">SHA-256 Hashed at Rest</span>
      </div>
      <div class="finding-detail mono" style="word-break:break-all;"><code>${esc(state.lastIssuedApiSecret)}</code></div>
      <div class="finding-rem">For security, the server stores only the SHA-256 digest and never returns this plaintext token again.</div>
    </div>
  `;
}

function renderApiKeys() {
  const wrap = document.getElementById("api-keys-table-wrap");
  const bearerInput = document.getElementById("v1-bearer-input");
  if (bearerInput && state.lastIssuedApiSecret && !bearerInput.value) {
    bearerInput.value = state.lastIssuedApiSecret;
  }
  const activeKey = bearerInput?.value.trim() || state.lastIssuedApiSecret || "<YOUR_REA_API_KEY>";
  const origin = window.location.origin;

  renderOneTimeKeyBanner();

  document.getElementById("curl-snippet-box").textContent =
    `curl -sS -X POST "${origin}/api/v1/xray" \\\n` +
    `  -H "Authorization: Bearer ${activeKey}" \\\n` +
    `  -H "Content-Type: application/json" \\\n` +
    `  -d '{"target":"acme-desktop-v1"}'`;

  const ciBox = document.getElementById("ci-snippet-box");
  if (ciBox) {
    ciBox.textContent =
      `# Zero-install CI/CD PR Gate (exits 1 when release_gate === "BLOCKED")\n` +
      `curl -fsSL "${origin}/api/ci/shipgate-cli.mjs" -o /tmp/shipgate-cli.mjs\n` +
      `REA_STUDIO_URL="${origin}" REA_API_KEY="${activeKey}" \\\n` +
      `  node /tmp/shipgate-cli.mjs xray ./dist/app.asar`;
  }

  if (!state.authenticated) {
    wrap.innerHTML = `<div class="muted-sm">Sign in to view or issue workspace API keys.</div>`;
    return;
  }

  wrap.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Key Label</th>
          <th>Key Prefix (Hashed)</th>
          <th>Plan</th>
          <th>Metered Calls</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${state.apiKeys
          .map(
            (k) => `
          <tr>
            <td><strong>${esc(k.name)}</strong></td>
            <td class="mono"><code>${esc(k.prefix || "rea_sk_****")}</code></td>
            <td><span class="pill pill-amber">${esc(state.tenant?.plan_name || "Trial")}</span></td>
            <td class="mono">${k.calls}</td>
            <td><button class="btn btn-sm btn-outline" data-revoke-key="${esc(k.id)}">Revoke</button></td>
          </tr>`,
          )
          .join("")}
      </tbody>
    </table>
  `;

  wrap.querySelectorAll("[data-revoke-key]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const res = await api("/api/keys/revoke", {
        method: "POST",
        body: JSON.stringify({ key_id: btn.dataset.revokeKey }),
      });
      if (res.ok) {
        state.apiKeys = res.api_keys;
        renderApiKeys();
        toast("API key revoked");
      }
    });
  });
}

function renderEvidenceTable(records) {
  const wrap = document.getElementById("evidence-ledger-wrap");
  if (!records.length) {
    wrap.innerHTML = `<div class="muted-sm">No Evidence sealed in this workspace yet. Sign in and run a scan in Tabs 1–3.</div>`;
    return;
  }
  wrap.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Evidence ID</th>
          <th>Operation</th>
          <th>Target</th>
          <th>Authority / Confidence</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${records
          .map(
            (r) => `
          <tr>
            <td class="mono"><code>${esc(shortHash(r.evidence_id, 20))}</code></td>
            <td class="mono">${esc(r.operation)}</td>
            <td>${esc(r.label)}</td>
            <td><span class="pill pill-cyan">${esc(r.authority)} · ${esc(r.confidence)}</span></td>
            <td class="btn-group">
              <button class="btn btn-sm btn-outline" data-open-ev="${esc(r.evidence_id)}">View JSON</button>
              <a class="btn btn-sm btn-secondary" href="/api/evidence/${encodeURIComponent(r.evidence_id)}/report?format=md" target="_blank" rel="noopener">Audit .md</a>
            </td>
          </tr>`,
          )
          .join("")}
      </tbody>
    </table>
  `;
  wrap.querySelectorAll("[data-open-ev]").forEach((btn) => {
    btn.addEventListener("click", () => openEvidenceModal(btn.dataset.openEv));
  });
}

async function openEvidenceModal(evidenceId) {
  if (!evidenceId) return;
  const res = await api(`/api/evidence/${encodeURIComponent(evidenceId)}`);
  if (!res.ok) {
    toast(res.error?.message || "Evidence envelope not found");
    return;
  }
  const modal = document.getElementById("evidence-modal");
  document.getElementById("modal-title").textContent = `REA Authenticated Evidence — ${res.record.operation}`;
  document.getElementById("modal-subtitle").textContent = res.record.evidence_id;
  document.getElementById("modal-dl-md").href = `/api/evidence/${encodeURIComponent(evidenceId)}/report?format=md`;
  document.getElementById("modal-dl-json").href = `/api/evidence/${encodeURIComponent(evidenceId)}/report?format=json`;
  document.getElementById("modal-json-body").textContent = JSON.stringify(res.record.evidence, null, 2);
  modal.classList.remove("hidden");
}

function wireAuthenticatedDownloads() {
  document.addEventListener("click", async (e) => {
    const anchor = e.target.closest("a[href]");
    if (!anchor) return;
    const href = anchor.getAttribute("href") || "";
    const isProtectedReport = href.startsWith("/api/evidence/") && href.includes("/report");
    const isProtectedZip = href.startsWith("/api/rl/download/");
    if (!isProtectedReport && !isProtectedZip) return;

    e.preventDefault();
    if (!state.authenticated) {
      document.getElementById("account-modal")?.classList.remove("hidden");
      toast("Sign in to download workspace Evidence and AgentEnv bundles.");
      return;
    }
    try {
      const resp = await fetch(href, {
        credentials: "same-origin",
      });
      if (!resp.ok) {
        toast("Authorized artifact not found or session expired.");
        return;
      }
      const blob = await resp.blob();
      const disp = resp.headers.get("content-disposition") || "";
      const match = disp.match(/filename="([^"]+)"/);
      const fallbackName = isProtectedZip ? "agentenv.zip" : href.includes("format=json") ? "evidence.json" : "audit.md";
      const url = URL.createObjectURL(blob);
      const dl = document.createElement("a");
      dl.href = url;
      dl.download = match?.[1] || fallbackName;
      document.body.appendChild(dl);
      dl.click();
      setTimeout(() => {
        dl.remove();
        URL.revokeObjectURL(url);
      }, 500);
    } catch {
      toast("Download failed");
    }
  });
}

// ============================================================================
// Bootstrap & Event Wiring
// ============================================================================
async function init() {
  setupTabs();
  setupRevenueSimulator();
  wireAuthenticatedDownloads();

  document.getElementById("modal-close-btn").addEventListener("click", () => {
    document.getElementById("evidence-modal").classList.add("hidden");
  });
  document.getElementById("evidence-modal").addEventListener("click", (e) => {
    if (e.target.id === "evidence-modal") e.currentTarget.classList.add("hidden");
  });

  // Account & Stripe Billing Modals
  document.getElementById("btn-open-account").addEventListener("click", () => {
    document.getElementById("account-modal").classList.remove("hidden");
  });
  document.getElementById("account-close-btn").addEventListener("click", () => {
    document.getElementById("account-modal").classList.add("hidden");
  });
  document.getElementById("btn-open-upgrade").addEventListener("click", () => {
    openBillingModal();
  });
  document.getElementById("billing-close-btn").addEventListener("click", () => {
    document.getElementById("billing-modal").classList.add("hidden");
  });

  document.querySelectorAll("[data-checkout-plan]").forEach((btn) => {
    btn.addEventListener("click", () => startPlanCheckout(btn.dataset.checkoutPlan));
  });

  document.getElementById("v1-bearer-input")?.addEventListener("input", () => renderApiKeys());

  document.getElementById("register-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        org_name: document.getElementById("reg-org").value,
        email: document.getElementById("reg-email").value,
        password: document.getElementById("reg-pass").value,
      }),
    });
    if (!res.ok) {
      toast(res.error?.message || "Registration failed");
      return;
    }
    state.authenticated = true;
    state.csrfToken = res.csrf_token || state.csrfToken;
    if (res.starter_api_key?.secret_token) {
      state.lastIssuedApiSecret = res.starter_api_key.secret_token;
      const bearerInput = document.getElementById("v1-bearer-input");
      if (bearerInput) bearerInput.value = state.lastIssuedApiSecret;
    }
    state.apiKeys = res.api_keys || [];
    renderTenantTopbar(res.tenant);
    renderApiKeys();
    document.getElementById("account-modal").classList.add("hidden");
    toast(`Created isolated workspace ${res.tenant.org_name}`);
    await runXraySample("acme-desktop-v1");
  });

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: document.getElementById("login-email").value,
        password: document.getElementById("login-pass").value,
      }),
    });
    if (!res.ok) {
      toast(res.error?.message || "Sign-in failed");
      return;
    }
    state.authenticated = true;
    state.csrfToken = res.csrf_token || state.csrfToken;
    state.lastIssuedApiSecret = "";
    state.apiKeys = res.api_keys || [];
    renderTenantTopbar(res.tenant);
    renderApiKeys();
    document.getElementById("account-modal").classList.add("hidden");
    toast(`Signed in to ${res.tenant.org_name}`);
    await runXraySample("acme-desktop-v1");
  });

  document.getElementById("btn-logout-sess").addEventListener("click", async () => {
    if (state.authenticated) {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: state.csrfToken ? { "x-csrf-token": state.csrfToken } : {},
      }).catch(() => {});
    }
    state.authenticated = false;
    state.csrfToken = "";
    state.tenant = null;
    state.lastIssuedApiSecret = "";
    state.apiKeys = [];
    renderTenantTopbar(null);
    renderApiKeys();
    renderEvidenceTable([]);
    renderUnauthenticatedPrompt("xray-results-area");
    document.getElementById("account-modal").classList.add("hidden");
    toast("Signed out and revoked workspace session");
  });

  document.getElementById("xray-trace-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runFeatureTrace();
  });
  document.getElementById("btn-compare-versions").addEventListener("click", runVersionComparison);
  document.getElementById("btn-refresh-evidence").addEventListener("click", loadCommercialTab);

  document.getElementById("btn-create-key").addEventListener("click", async () => {
    const res = await api("/api/keys/create", {
      method: "POST",
      body: JSON.stringify({ name: `CI Key #${state.apiKeys.length + 1}` }),
    });
    if (res.ok) {
      if (res.key?.secret_token) {
        state.lastIssuedApiSecret = res.key.secret_token;
        const bearerInput = document.getElementById("v1-bearer-input");
        if (bearerInput) bearerInput.value = state.lastIssuedApiSecret;
      }
      state.apiKeys = res.api_keys;
      renderApiKeys();
      toast("Issued new API key — copy secret token now (shown once)");
    } else if (res.error?.message) {
      toast(res.error.message);
    }
  });

  document.querySelectorAll("[data-v1-test]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const kind = btn.dataset.v1Test;
      const bearerInput = document.getElementById("v1-bearer-input");
      const activeKey = bearerInput?.value.trim() || state.lastIssuedApiSecret || "";
      if (!activeKey) {
        toast("Issue a new API key or paste your rea_sk_live_... secret token first.");
        return;
      }
      const url = `/api/v1/${kind}`;
      const res = await fetch(url, {
        method: kind === "status" ? "GET" : "POST",
        headers: {
          authorization: `Bearer ${activeKey}`,
          "content-type": "application/json",
        },
        ...(kind === "status" ? {} : { body: JSON.stringify({}) }),
      });
      const json = await res.json();
      document.getElementById("v1-response-box").textContent = JSON.stringify(json, null, 2).slice(0, 3500);
      await loadCommercialTab();
      toast(`${res.ok ? "Authenticated" : "Rejected"} ${url} (${res.status})`);
    });
  });

  // Upload handlers across all 3 suites
  wireDropzone("xray-dropzone", "xray-file-input", "xray-browse-btn", async (file) => {
    try {
      toast(`Uploading ${file.name}…`);
      const up = await uploadFile(file);
      const res = await api("/api/xray/scan", {
        method: "POST",
        body: JSON.stringify({ saved_path: up.saved_path }),
      });
      if (res.ok) {
        state.currentXray = res;
        renderXrayResult(res);
        toast(`Scanned ${file.name}`);
      } else {
        toast(res.error?.message || "Failed to analyze uploaded JS/ASAR");
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Upload failed");
    }
  });

  wireDropzone("shipgate-dropzone", "shipgate-file-input", "shipgate-browse-btn", async (file) => {
    try {
      toast(`Uploading ${file.name}…`);
      const up = await uploadFile(file);
      const res = await api("/api/shipgate/inspect", {
        method: "POST",
        body: JSON.stringify({ saved_path: up.saved_path }),
      });
      if (res.ok) {
        state.currentShipgate = res;
        renderShipGateResult(res);
        toast(`Inspected ${file.name}`);
      } else {
        toast(res.error?.message || "Inspection failed");
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Upload failed");
    }
  });

  wireDropzone("rl-dropzone", "rl-file-input", "rl-browse-btn", async (file) => {
    try {
      toast(`Uploading ${file.name}…`);
      const up = await uploadFile(file);
      const res = await api("/api/rl/build", {
        method: "POST",
        body: JSON.stringify({ saved_path: up.saved_path }),
      });
      if (res.ok) {
        state.currentRl = res;
        renderRlStudio(res);
        toast(`Built & launched live AgentEnv from ${file.name}`);
      } else {
        toast(res.error?.message || "HAR build failed");
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Upload failed");
    }
  });

  // Initial bootstrap (safe read-only; only runs scan if valid workspace session exists)
  const boot = await api("/api/bootstrap");
  if (boot.ok) {
    state.bootstrap = boot;
    renderXraySampleList("acme-desktop-v1");
    renderShipgateSampleList("libvault-elf");
    renderRlSampleList("helpdesk-crm");

    if (boot.authenticated && boot.tenant) {
      state.authenticated = true;
      state.csrfToken = boot.csrf_token || state.csrfToken;
      state.apiKeys = boot.api_keys || [];
      renderTenantTopbar(boot.tenant);
      renderApiKeys();
      await refreshLedgerCounter();
    } else {
      state.authenticated = false;
      state.csrfToken = "";
      renderTenantTopbar(null);
      renderUnauthenticatedPrompt("xray-results-area");
    }
  }
}

init().catch((err) => {
  const area = document.getElementById("xray-results-area");
  if (area) {
    area.innerHTML = `<div class="card"><span class="pill pill-red">Startup Error</span> ${esc(err?.message || String(err))}</div>`;
  }
});
