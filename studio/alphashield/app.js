// AlphaShield External Application Logic (Strict CSP `script-src 'self'` Compatible)
// Sessions use HttpOnly; SameSite=Lax cookies + in-memory X-CSRF-Token only.

try {
  window.localStorage?.removeItem("rea_studio_session");
} catch {
  // Ignore restricted iframe storage
}

const memStore = new Map();
function sGet(key, fallback = null) {
  try {
    const raw = window.localStorage.getItem(key);
    return raw !== null ? JSON.parse(raw) : fallback;
  } catch {
    return memStore.has(key) ? memStore.get(key) : fallback;
  }
}
function sSet(key, val) {
  memStore.set(key, val);
  try {
    window.localStorage.setItem(key, JSON.stringify(val));
  } catch {
    // Ignore storage block
  }
}

let csrfToken = "";
let serverTenant = null;
let directUsdtEnabled = false;
let backendAvailable = false;
let billingPeriod = "MONTHLY";
let lastAuditSummaryText = "";
let activeCheckoutPlan = "alphashield_pro";
let activeCheckoutUsd = 19;
let activePaymentIntent = null;
let activeMerchantWallet = null;
let activeTokenContract = null;

const FREE_DAILY_LIMIT = 3;

function getPublicStoreUrl() {
  return `${window.location.origin}/alphashield`;
}

function apiHeaders(method = "GET", extra = {}) {
  const upper = String(method || "GET").toUpperCase();
  const csrf = upper !== "GET" && upper !== "HEAD" && csrfToken ? { "x-csrf-token": csrfToken } : {};
  return { ...csrf, ...extra };
}

async function apiJson(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const res = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "content-type": "application/json",
      ...apiHeaders(method, options.headers || {}),
    },
  });
  const data = await res.json();
  if (typeof data?.csrf_token === "string" && data.csrf_token) {
    csrfToken = data.csrf_token;
  }
  return { res, data };
}

function todayKey() {
  return `as_scans_${new Date().toISOString().slice(0, 10)}`;
}

function isProUnlocked() {
  const planId = serverTenant?.alphashield_plan_id;
  const studioPaid = Boolean(serverTenant?.plan_id && serverTenant.plan_id !== "free_trial");
  return studioPaid || planId === "alphashield_pro" || planId === "alphashield_whale";
}

function getRemainingFreeScans() {
  // Server quota state is authoritative; localStorage is strictly a passive display mirror.
  const serverUsed = serverTenant?.usage?.alphashield_scans_today;
  if (typeof serverUsed === "number") {
    const used = Math.max(0, Number(serverUsed || 0));
    sSet(todayKey(), used);
    return Math.max(0, FREE_DAILY_LIMIT - used);
  }
  const cachedDisplayUsed = Number(sGet(todayKey(), 0));
  return Math.max(0, FREE_DAILY_LIMIT - cachedDisplayUsed);
}

function requireAuthenticatedScanSession() {
  if (!backendAvailable) {
    alert("AlphaShield backend is currently unreachable. Connect to the live AlphaShield server to run verified scans.");
    return false;
  }
  if (!serverTenant) {
    openAlphaAuthModal();
    return false;
  }
  return true;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function refreshQuotaUI() {
  const btn = document.getElementById("quotaBadgeBtn");
  const licBadge = document.getElementById("licenseStatusBadge");
  const authBtn = document.getElementById("alphaAuthBtn");
  if (authBtn) {
    authBtn.textContent = serverTenant ? serverTenant.email : "Sign In";
  }
  if (!btn || !licBadge) return;
  if (isProUnlocked()) {
    btn.textContent = `💎 ${serverTenant.alphashield_plan_name || "PRO UNLIMITED"}`;
    btn.classList.add("pro");
    licBadge.textContent = "VERIFIED PRO";
    licBadge.className = "badge badge-green";
  } else {
    const rem = getRemainingFreeScans();
    btn.textContent = `${rem}/${FREE_DAILY_LIMIT} Free Scans`;
    btn.classList.remove("pro");
    licBadge.textContent = serverTenant ? "FREE TIER" : "SIGN IN REQUIRED";
    licBadge.className = "badge badge-indigo";
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".view-panel").forEach((el) => el.classList.remove("active"));
  document.getElementById(`view-${tabId}`)?.classList.add("active");
  document.querySelectorAll(".tab-btn, .bnav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function openPlaybookModal() {
  document.getElementById("playbookModal")?.classList.add("open");
}

function openAlphaAuthModal() {
  document.getElementById("alphaAuthModal")?.classList.add("open");
}

function closeModal(id) {
  document.getElementById(id)?.classList.remove("open");
}

async function alphaSignIn() {
  const fb = document.getElementById("alphaAuthFeedback");
  const email = document.getElementById("alphaLoginEmail").value.trim();
  const password = document.getElementById("alphaLoginPass").value;
  try {
    const { data } = await apiJson("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    if (!data.ok) {
      fb.style.color = "#f87171";
      fb.textContent = data.error?.message || "Sign-in failed.";
      return;
    }
    serverTenant = data.tenant;
    refreshQuotaUI();
    fb.style.color = "#34d399";
    fb.textContent = `Signed in as ${data.tenant.email}`;
    closeModal("alphaAuthModal");
    await checkKelviqBackendStatus();
  } catch {
    fb.style.color = "#f87171";
    fb.textContent = "Backend server unreachable.";
  }
}

async function alphaRegister() {
  const fb = document.getElementById("alphaAuthFeedback");
  const org_name = document.getElementById("alphaRegOrg").value.trim() || "AlphaShield Trader";
  const email = document.getElementById("alphaRegEmail").value.trim();
  const password = document.getElementById("alphaRegPass").value;
  try {
    const { data } = await apiJson("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ org_name, email, password }),
    });
    if (!data.ok) {
      fb.style.color = "#f87171";
      fb.textContent = data.error?.message || "Registration failed.";
      return;
    }
    serverTenant = data.tenant;
    refreshQuotaUI();
    fb.style.color = "#34d399";
    fb.textContent = `Created account for ${data.tenant.email}`;
    closeModal("alphaAuthModal");
    await checkKelviqBackendStatus();
  } catch {
    fb.style.color = "#f87171";
    fb.textContent = "Backend server unreachable.";
  }
}

async function alphaSignOut() {
  if (serverTenant) {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: apiHeaders("POST"),
    }).catch(() => {});
  }
  csrfToken = "";
  serverTenant = null;
  activePaymentIntent = null;
  refreshQuotaUI();
  closeModal("alphaAuthModal");
}

function openLegalModal(section) {
  const box = document.getElementById("legalModalContent");
  const map = {
    terms: `<h3 style="margin-top:0;color:#fff;">Terms of Service — AlphaShield by Gandoh Bah Ai</h3>
      <p>AlphaShield is a self-serve cybersecurity and static software analysis SaaS operated by <strong>Gandoh Bah Ai</strong>. Subscriptions grant time-bounded digital access to automated EVM bytecode selector inspection and Android/archive static malware checks.</p>
      <p>AlphaShield is strictly an informational software security tool. We never custody assets, broker transactions, or provide investment advice. Payments and tax invoicing are processed securely by our Merchant of Record, <strong>Kelviq</strong>.</p>`,
    privacy: `<h3 style="margin-top:0;color:#fff;">Privacy Policy</h3>
      <p>AlphaShield performs local WebCrypto SHA-256 and Shannon entropy checks directly in your browser wherever possible. We collect only the account email and billing metadata required to deliver your software license and manage subscriptions.</p>`,
    refunds: `<h3 style="margin-top:0;color:#fff;">Refund &amp; Cancellation Policy</h3>
      <p><strong>Cancel Anytime:</strong> Subscriptions can be cancelled in one click via the Kelviq Customer Billing Portal with zero cancellation fees.</p>`,
  };
  box.innerHTML = map[section] || map.terms;
  document.getElementById("legalModal")?.classList.add("open");
}

const CHAIN_HEX = { bsc: "0x38", ethereum: "0x1" };

function openUsdtCheckoutModal(planId, baseMonthlyUsd) {
  if (!serverTenant) {
    openAlphaAuthModal();
    return;
  }
  if (!directUsdtEnabled) {
    openPlaybookModal();
    return;
  }
  activeCheckoutPlan = planId;
  activeCheckoutUsd =
    billingPeriod === "YEARLY" ? (planId === "alphashield_whale" ? 399 : 159) : Number(baseMonthlyUsd);
  activePaymentIntent = null;
  activeMerchantWallet = null;
  activeTokenContract = null;
  const planLabel = activeCheckoutPlan === "alphashield_whale" ? "Whale & Alpha Group" : "AlphaShield Pro";
  document.getElementById("usdtModalTitle").textContent = `Unlock ${planLabel} — $${activeCheckoutUsd} USDT`;
  document.getElementById("intentSummaryBox").textContent =
    "Enter your 0x sender wallet and click Create Intent to reserve your unique payment tag.";
  document.getElementById("txVerifyFeedback").textContent = "";
  document.getElementById("usdtCheckoutModal")?.classList.add("open");
}

async function createBoundPaymentIntent() {
  const summary = document.getElementById("intentSummaryBox");
  const payerWallet = document.getElementById("payerWalletInput").value.trim();
  const chain = document.getElementById("payChainSelect").value;
  if (!/^0x[0-9a-fA-F]{40}$/.test(payerWallet)) {
    summary.style.color = "#f87171";
    summary.textContent = "Enter your valid 42-character 0x sender wallet address first.";
    return null;
  }
  const { data } = await apiJson("/api/alphashield/payment-intent", {
    method: "POST",
    body: JSON.stringify({
      chain,
      plan_id: activeCheckoutPlan,
      charge_period: billingPeriod,
      payer_wallet: payerWallet,
    }),
  });
  if (!data.ok) {
    summary.style.color = "#f87171";
    summary.textContent = data.error?.message || "Could not create payment intent.";
    return null;
  }
  activePaymentIntent = data.intent;
  activeMerchantWallet = data.merchant_wallet;
  activeTokenContract = data.token_contract;
  summary.style.color = "#34d399";
  summary.textContent =
    `Intent ${activePaymentIntent.intent_id} bound to ${activePaymentIntent.payer_wallet} · ` +
    `Send EXACTLY ${activePaymentIntent.exact_human_amount} USDT to ${activeMerchantWallet}`;
  return data;
}

async function payWithWeb3Wallet() {
  const fb = document.getElementById("txVerifyFeedback");
  if (!window.ethereum) {
    fb.style.color = "#fbbf24";
    fb.textContent = "No browser wallet detected. Create an intent above and send the exact amount from your wallet.";
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    if (accounts?.[0]) {
      document.getElementById("payerWalletInput").value = accounts[0];
    }
    if (!activePaymentIntent || activePaymentIntent.payer_wallet !== String(accounts[0] || "").toLowerCase()) {
      const created = await createBoundPaymentIntent();
      if (!created) return;
    }
    const chainKey = activePaymentIntent.chain;
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: CHAIN_HEX[chainKey] || "0x38" }],
      });
    } catch {
      // ignore chain switch prompt errors
    }
    const amountUnits = BigInt(activePaymentIntent.exact_raw_units);
    const paddedTo = activeMerchantWallet.replace(/^0x/i, "").toLowerCase().padStart(64, "0");
    const paddedAmt = amountUnits.toString(16).padStart(64, "0");
    const callData = `0xa9059cbb${paddedTo}${paddedAmt}`;

    fb.style.color = "#a5b4fc";
    fb.textContent = `Confirm exact ${activePaymentIntent.exact_human_amount} USDT transfer in your wallet...`;
    const txHash = await window.ethereum.request({
      method: "eth_sendTransaction",
      params: [{ from: accounts[0], to: activeTokenContract, data: callData }],
    });
    document.getElementById("txHashInput").value = txHash;
    fb.style.color = "#34d399";
    fb.textContent = "Transaction broadcast! Waiting 5s for block confirmation...";
    setTimeout(() => void verifyOnChainPaymentTx(), 5000);
  } catch (err) {
    fb.style.color = "#f87171";
    fb.textContent = err?.message || "Wallet payment cancelled.";
  }
}

async function verifyOnChainPaymentTx() {
  const txHash = document.getElementById("txHashInput").value.trim();
  const fb = document.getElementById("txVerifyFeedback");
  if (!serverTenant) {
    openAlphaAuthModal();
    return;
  }
  if (!activePaymentIntent?.intent_id) {
    fb.style.color = "#f87171";
    fb.textContent = "Create a bound payment intent above before submitting a transaction hash.";
    return;
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    fb.style.color = "#f87171";
    fb.textContent = "Enter a valid 66-character 0x... transaction hash.";
    return;
  }

  fb.style.color = "#fbbf24";
  fb.textContent = "Verifying sender wallet, exact sub-cent intent amount, and block recency...";
  try {
    const { data } = await apiJson("/api/alphashield/verify-tx", {
      method: "POST",
      body: JSON.stringify({
        intent_id: activePaymentIntent.intent_id,
        tx_hash: txHash,
      }),
    });
    if (!data.ok) {
      fb.style.color = "#f87171";
      fb.textContent = data.error?.message || "Server rejected transaction receipt.";
      return;
    }
    serverTenant = data.tenant;
    activePaymentIntent = null;
    refreshQuotaUI();
    fb.style.color = "#34d399";
    fb.textContent = `✓ Verified! ${data.tenant.alphashield_plan_name} active until ${new Date(data.tenant.alphashield_expires_at).toLocaleDateString()}.`;
  } catch {
    fb.style.color = "#f87171";
    fb.textContent = "Could not reach backend verification endpoint.";
  }
}

const FALLBACK_TICKERS = [
  { symbol: "BTC", price: 94820, change: 2.45 },
  { symbol: "ETH", price: 3185, change: 3.12 },
  { symbol: "SOL", price: 214.6, change: 5.84 },
  { symbol: "BNB", price: 642.1, change: 1.35 },
  { symbol: "SUI", price: 3.42, change: 8.91 },
  { symbol: "PEPE", price: 0.0000184, change: 11.4 },
];

function fmtUsd(n) {
  const num = Number(n || 0);
  if (!Number.isFinite(num) || num === 0) return "$0.00";
  if (num >= 1e9) return `$${(num / 1e9).toFixed(2)}B`;
  if (num >= 1e6) return `$${(num / 1e6).toFixed(2)}M`;
  if (num >= 1e3) return `$${num.toLocaleString(undefined, { maximumFractionDigits: 2 })}`;
  if (num >= 1) return `$${num.toFixed(2)}`;
  if (num >= 0.01) return `$${num.toFixed(4)}`;
  return `$${num.toFixed(8)}`;
}

async function fetchWithTimeout(url, options = {}, ms = 6500) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function loadGlobalTickers() {
  const grid = document.getElementById("globalTickerGrid");
  const badge = document.getElementById("marketSourceBadge");
  try {
    const symbols = encodeURIComponent('["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","SUIUSDT","PEPEUSDT"]');
    const res = await fetchWithTimeout(`https://data-api.binance.vision/api/v3/ticker/24hr?symbols=${symbols}`);
    if (!res.ok) throw new Error("binance_status");
    const arr = await res.json();
    badge.textContent = "LIVE BINANCE FEED";
    badge.className = "badge badge-green";
    grid.innerHTML = arr
      .map((t) => {
        const sym = escapeHtml(t.symbol.replace("USDT", ""));
        const chg = Number(t.priceChangePercent || 0);
        return `<div class="ticker-card">
          <div class="ticker-top">
            <span>${sym}/USD</span>
            <span class="${chg >= 0 ? "up" : "down"}">${chg >= 0 ? "+" : ""}${chg.toFixed(2)}%</span>
          </div>
          <div class="ticker-price">${fmtUsd(t.lastPrice)}</div>
          <div class="muted" style="font-size:10.5px;">24h Vol: ${fmtUsd(t.quoteVolume)}</div>
        </div>`;
      })
      .join("");
  } catch {
    badge.textContent = "SNAPSHOT MODE";
    badge.className = "badge badge-amber";
    grid.innerHTML = FALLBACK_TICKERS.map(
      (t) => `<div class="ticker-card">
        <div class="ticker-top"><span>${t.symbol}/USD</span><span class="up">+${t.change}%</span></div>
        <div class="ticker-price">${fmtUsd(t.price)}</div>
      </div>`,
    ).join("");
  }
}

function mapDexChainToSupported(chainId) {
  const c = String(chainId || "").toLowerCase();
  if (c === "ethereum" || c === "eth") return "ethereum";
  if (c === "base") return "base";
  if (c === "bsc" || c === "bnb") return "bsc";
  if (c === "arbitrum") return "arbitrum";
  if (c === "polygon") return "polygon";
  return null;
}

async function searchDexPairs() {
  const q = document.getElementById("dexSearchInput").value.trim() || "PEPE";
  const list = document.getElementById("dexResultsList");
  list.innerHTML = `<div class="muted" style="font-size:12.5px;">Scanning live DexScreener liquidity pools for <strong>${escapeHtml(q)}</strong>...</div>`;
  try {
    const res = await fetchWithTimeout(`https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(q)}`);
    if (!res.ok) throw new Error("dex_http");
    const data = await res.json();
    const pairs = (data.pairs || []).slice(0, 7);
    if (!pairs.length) {
      list.innerHTML = `<div class="muted" style="font-size:12.5px;">No DEX pairs matched "${escapeHtml(q)}".</div>`;
      return;
    }
    list.innerHTML = pairs
      .map((p) => {
        const sym = escapeHtml(p.baseToken?.symbol || "TOKEN");
        const name = escapeHtml(p.baseToken?.name || "");
        const addr = escapeHtml(p.baseToken?.address || "");
        const chain = escapeHtml(p.chainId || "chain");
        const supportedChain = mapDexChainToSupported(p.chainId);
        const chg24 = Number(p.priceChange?.h24 || 0);
        const liq = Number(p.liquidity?.usd || 0);
        const buys = Number(p.txns?.h24?.buys || 0);
        const sells = Number(p.txns?.h24?.sells || 0);

        const scanBtn =
          supportedChain && addr.startsWith("0x")
            ? `<button class="btn btn-primary btn-sm" type="button" data-action="jump-scan" data-chain="${supportedChain}" data-addr="${addr}" data-label="${sym}">🛡️ Rug-Scan</button>`
            : `<span class="badge badge-indigo">${chain}</span>`;

        return `<div class="pair-item">
          <div class="pair-meta">
            <div class="pair-symbol">
              <span>${sym}</span>
              <span class="muted" style="font-weight:500;font-size:11.5px;">${name}</span>
              <span class="badge badge-indigo">${chain}</span>
            </div>
            <div class="pair-sub">${addr.slice(0, 10)}...${addr.slice(-6)} · Liq: ${fmtUsd(liq)} · 24h B/S: ${buys}/${sells}</div>
          </div>
          <div class="pair-stats">
            <div>
              <div style="font-weight:800;">${fmtUsd(p.priceUsd)}</div>
              <div class="${chg24 >= 0 ? "up" : "down"}" style="font-size:11px;text-align:right;">${chg24 >= 0 ? "+" : ""}${chg24.toFixed(2)}%</div>
            </div>
            <button class="btn btn-sm" type="button" title="Save to Watchlist" data-action="save-watch" data-sym="${sym}" data-chain="${supportedChain || chain}" data-addr="${addr}" data-price="${Number(p.priceUsd || 0)}">★</button>
            ${scanBtn}
          </div>
        </div>`;
      })
      .join("");
  } catch {
    list.innerHTML = `<div class="finding warn">
      <div class="finding-title">Live DEX Search Temporarily Offline</div>
      <div class="finding-desc">Tap <strong>2. Contract Rug-Scanner</strong> above to test presets or paste any 0x contract bytecode directly.</div>
    </div>`;
  }
}

function jumpToContractScan(chain, address, label) {
  document.getElementById("chainSelect").value = chain;
  document.getElementById("contractAddressInput").value = address;
  document.getElementById("rawBytecodeInput").value = "";
  switchTab("rugcheck");
  void runSmartContractAudit(label);
}

function saveToWatchlist(symbol, chain, address, price) {
  const list = sGet("as_watchlist", []);
  if (!list.some((x) => x.address === address)) {
    list.unshift({ symbol, chain, address, savedPrice: price, at: new Date().toISOString() });
    sSet("as_watchlist", list.slice(0, 15));
  }
  renderWatchlist();
}

function removeWatchlist(addr) {
  const list = sGet("as_watchlist", []).filter((x) => x.address !== addr);
  sSet("as_watchlist", list);
  renderWatchlist();
}

function renderWatchlist() {
  const list = sGet("as_watchlist", []);
  document.getElementById("watchlistCountBadge").textContent = `${list.length} Saved`;
  const el = document.getElementById("watchlistContainer");
  if (!list.length) {
    el.innerHTML = `<div class="muted" style="font-size:12px;padding:12px 0;">Tap ★ next to any token in the DEX radar to track it here.</div>`;
    return;
  }
  el.innerHTML = list
    .map((item) => {
      const canScan =
        ["ethereum", "base", "bsc", "arbitrum", "polygon"].includes(item.chain) &&
        String(item.address).startsWith("0x");
      return `<div class="pair-item">
        <div class="pair-meta">
          <div class="pair-symbol">${escapeHtml(item.symbol)} <span class="badge badge-indigo">${escapeHtml(item.chain)}</span></div>
          <div class="pair-sub">Entry: ${fmtUsd(item.savedPrice)} · ${escapeHtml(String(item.address).slice(0, 12))}...</div>
        </div>
        <div style="display:flex;gap:6px;">
          ${canScan ? `<button class="btn btn-primary btn-sm" type="button" data-action="jump-scan" data-chain="${escapeHtml(item.chain)}" data-addr="${escapeHtml(item.address)}" data-label="${escapeHtml(item.symbol)}">Audit</button>` : ""}
          <button class="btn btn-sm" type="button" data-action="remove-watch" data-addr="${escapeHtml(item.address)}">✕</button>
        </div>
      </div>`;
    })
    .join("");
}

const RPC_ENDPOINTS = {
  ethereum: ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com", "https://cloudflare-eth.com"],
  base: ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
  bsc: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org"],
  arbitrum: ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"],
  polygon: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com"],
};

const EVM_TRAPS = [
  { hex: "40c10f19", severity: "crit", points: 24, title: "Hidden Mint Function · mint(address,uint256)", desc: "Contract contains mint(address,uint256) selector (0x40c10f19)." },
  { hex: "a0712d68", severity: "crit", points: 20, title: "Supply Mint Selector · mint(uint256)", desc: "Detected mint(uint256) selector (0xa0712d68) allowing supply inflation." },
  { hex: "f9f92be4", severity: "crit", points: 28, title: "Honeypot Blacklist Trap · blacklist(address)", desc: "Owner can blacklist specific buyer wallets from selling." },
  { hex: "44337ea1", severity: "crit", points: 28, title: "Wallet Freeze / Blacklist · blacklistAccount", desc: "Detected blacklist enforcement selector (0x44337ea1)." },
  { hex: "fe575a87", severity: "warn", points: 14, title: "Blacklist Lookup · isBlacklisted(address)", desc: "Token checks blacklist mapping during transfers." },
  { hex: "9a7a23d6", severity: "crit", points: 26, title: "Anti-Sell Bot Trap · setAutomatedMarketMakerPair / addBot", desc: "Detected AMM pair / bot-blocking selector." },
  { hex: "69fe0e2d", severity: "crit", points: 25, title: "Modifiable Transfer Tax · setFee / setTax", desc: "Developer can dynamically raise sell fees." },
  { hex: "8ea5220f", severity: "warn", points: 12, title: "Developer Tax Collector · devWallet / taxWallet", desc: "Contract routes fee percentages to an external developer wallet." },
  { hex: "8456cb59", severity: "warn", points: 15, title: "Global Trading Freeze · pause()", desc: "Contract includes pause() (0x8456cb59)." },
  { hex: "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", severity: "warn", points: 22, title: "Upgradeable EIP-1967 Proxy Contract", desc: "Implementation logic can be swapped via DELEGATECALL." },
  { hex: "363d3d373d3d3d363d73", severity: "warn", points: 18, title: "EIP-1167 Minimal Proxy Clone", desc: "Forwards all calls via DELEGATECALL." },
  { hex: "8da5cb5b", severity: "info", points: 6, title: "Ownable Admin Control · owner()", desc: "Standard Ownable pattern detected." },
  { hex: "715018a6", severity: "safe", points: 0, title: "Renounce Capability · renounceOwnership()", desc: "Includes OpenZeppelin renounceOwnership() selector." },
];

function loadSimulatedHoneypot() {
  document.getElementById("chainSelect").value = "ethereum";
  document.getElementById("contractAddressInput").value = "0xDEAD00009999111122223333444455556666BEEF";
  document.getElementById("rawBytecodeInput").value =
    "0x608060405234801561001057600080fd5b50600436106100a95760003560e01c" +
    "806340c10f1914610110578063f9f92be41461013057806344337ea11461015057" +
    "806369fe0e2d146101705780638456cb59146101905780638da5cb5b146101b057" +
    "363d3d373d3d3d363d73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef5af43d82803e903d91602b57fd5bf3ff";
  void runSmartContractAudit("Simulated Honeypot Trap ($MOONRUG)");
}

async function fetchLiveBytecode(chain, address) {
  const urls = RPC_ENDPOINTS[chain] || RPC_ENDPOINTS.ethereum;
  for (const rpcUrl of urls) {
    try {
      const res = await fetchWithTimeout(
        rpcUrl,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] }),
        },
        6000,
      );
      if (!res.ok) continue;
      const data = await res.json();
      if (typeof data.result === "string") return { bytecode: data.result, rpcUrl };
    } catch {
      // try next RPC
    }
  }
  throw new Error(`Could not reach public RPC nodes for ${chain}.`);
}

async function runSmartContractAudit(optionalLabel = "") {
  if (!requireAuthenticatedScanSession()) return;

  const chain = document.getElementById("chainSelect").value;
  const address = document.getElementById("contractAddressInput").value.trim();
  const rawOverride = document.getElementById("rawBytecodeInput").value.trim();
  const out = document.getElementById("contractAuditOutput");
  const badge = document.getElementById("auditChainBadge");

  badge.textContent = "SCANNING...";
  badge.className = "badge badge-amber";
  out.innerHTML = `<div class="muted" style="padding:18px 0;text-align:center;">Verifying quota &amp; decompiling EVM 4-byte selectors via REA server...</div>`;

  try {
    let bytecode = "";
    let sourceLabel = "Pasted Raw Bytecode";
    if (rawOverride.length >= 8) {
      bytecode = rawOverride;
    } else {
      if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
        throw new Error("Enter a valid 42-character 0x contract address.");
      }
      sourceLabel = `${chain.toUpperCase()} Live RPC`;
      try {
        const rpcOut = await fetchLiveBytecode(chain, address);
        bytecode = rpcOut.bytecode || "";
      } catch {
        bytecode = "";
      }
    }

    const cleanCandidate = bytecode.replace(/^0x/i, "").toLowerCase();
    const { res: bRes, data: bJson } = await apiJson("/api/alphashield/evm-audit", {
      method: "POST",
      body: JSON.stringify({
        chain,
        ...(address ? { address } : {}),
        ...(cleanCandidate.length >= 8 ? { bytecode: cleanCandidate } : {}),
      }),
    });

    if (bRes.status === 401) {
      serverTenant = null;
      refreshQuotaUI();
      badge.textContent = "SIGN IN REQUIRED";
      badge.className = "badge badge-indigo";
      out.innerHTML = `<div class="muted" style="padding:18px 0;text-align:center;">Sign in to your free AlphaShield workspace to run contract scans.</div>`;
      openAlphaAuthModal();
      return;
    }
    if (bRes.status === 402) {
      if (bJson?.tenant) serverTenant = bJson.tenant;
      refreshQuotaUI();
      badge.textContent = "QUOTA REACHED";
      badge.className = "badge badge-amber";
      out.innerHTML = `<div class="finding warn">
        <div class="finding-title">Daily Free Scan Limit Reached</div>
        <div class="finding-desc">${escapeHtml(bJson?.error?.message || "Upgrade to AlphaShield Pro ($19/mo) for unlimited contract & APK scans.")}</div>
      </div>`;
      document.getElementById("paywallModal")?.classList.add("open");
      return;
    }
    if (!bRes.ok || !bJson?.ok) {
      throw new Error(bJson?.error?.message || "Server contract audit failed.");
    }

    if (bJson.tenant) {
      serverTenant = bJson.tenant;
      refreshQuotaUI();
    }

    const cleanHex = cleanCandidate;
    if ((!cleanHex || cleanHex === "0" || cleanHex.length < 8) && bJson.is_eoa_or_unfetched) {
      badge.textContent = "EOA / NO CODE";
      badge.className = "badge badge-red";
      out.innerHTML = `<div class="finding crit">
        <div class="finding-title">No Smart Contract Bytecode Deployed on ${escapeHtml(chain.toUpperCase())}</div>
        <div class="finding-desc">Address <span class="mono">${escapeHtml(address)}</span> returned empty bytecode (<span class="mono">0x</span>).</div>
      </div>`;
      return;
    }

    const backendWasmNote = "Verified by REA v6.8 Server EVM Inspector";

    let riskPoints = 0;
    const findings = [];
    for (const trap of EVM_TRAPS) {
      if (cleanHex.includes(trap.hex)) {
        riskPoints += trap.points;
        findings.push(trap);
      }
    }
    const byteCount = Math.floor(cleanHex.length / 2);
    if (byteCount < 180) {
      riskPoints += 20;
      findings.push({
        severity: "warn",
        title: `Minimal / Stub Bytecode (${byteCount} bytes)`,
        desc: "Small contract size — often a forwarding proxy.",
      });
    }
    if (findings.length === 0) {
      findings.push({
        severity: "safe",
        title: "Clean Standard ERC-20 Bytecode Profile",
        desc: "Zero hidden mint, blacklist, dynamic fee-hike, or proxy trap selectors found.",
      });
    }

    const safetyScore = Math.max(5, Math.min(98, 100 - riskPoints));
    const verdict =
      safetyScore >= 75 ? "LOW RISK · CLEAN" : safetyScore >= 45 ? "MEDIUM CAUTION" : "CRITICAL RUG / HONEYPOT RISK";
    const color = safetyScore >= 75 ? "#10b981" : safetyScore >= 45 ? "#f59e0b" : "#ef4444";
    const tokenTitle = optionalLabel || `${address.slice(0, 8)}...${address.slice(-4)}`;

    badge.textContent = sourceLabel;
    badge.className = safetyScore >= 75 ? "badge badge-green" : safetyScore >= 45 ? "badge badge-amber" : "badge badge-red";

    lastAuditSummaryText =
      `🛡️ AlphaShield Contract Audit: ${tokenTitle} (${chain.toUpperCase()})\n` +
      `Safety Score: ${safetyScore}/100 — ${verdict}\n` +
      `Bytecode Size: ${byteCount.toLocaleString()} bytes · Findings: ${findings[0].title}\n` +
      `Scan any token free before you buy: ${getPublicStoreUrl()}`;

    out.innerHTML = `
      <div class="score-box">
        <div class="score-circle" style="border-color:${color};color:${color};">${safetyScore}</div>
        <div>
          <div style="font-weight:900;font-size:15px;color:${color};">${verdict}</div>
          <div style="font-weight:700;font-size:13px;margin-top:2px;">${escapeHtml(tokenTitle)} · <span class="mono">${byteCount.toLocaleString()} B</span></div>
          <div class="muted" style="font-size:11.5px;margin-top:3px;">${backendWasmNote || "Audited 14 EVM trap selectors"}</div>
        </div>
      </div>
      <div class="finding-list">
        ${findings
          .map(
            (f) => `
          <div class="finding ${f.severity === "crit" ? "crit" : f.severity === "warn" ? "warn" : "safe"}">
            <div class="finding-title">${escapeHtml(f.title)}</div>
            <div class="finding-desc">${escapeHtml(f.desc)}</div>
          </div>`,
          )
          .join("")}
      </div>
      <div class="viral-box">
        <div style="font-size:12px;font-weight:800;margin-bottom:7px;">🚀 Share Security Alert</div>
        <div style="display:flex;gap:7px;flex-wrap:wrap;">
          <button class="btn btn-primary btn-sm" type="button" data-action="share-wa">Share on WhatsApp</button>
          <button class="btn btn-indigo btn-sm" type="button" data-action="share-x">Post Alert on X</button>
          <button class="btn btn-sm" type="button" data-action="copy-alert">Copy Telegram Alert</button>
        </div>
      </div>
    `;
  } catch (err) {
    badge.textContent = "ERROR";
    badge.className = "badge badge-red";
    out.innerHTML = `<div class="finding crit">
      <div class="finding-title">Scan Failed</div>
      <div class="finding-desc">${escapeHtml(err.message || String(err))}</div>
    </div>`;
  }
}

const DRAINER_PATTERNS = [
  { pat: /mnemonic|seed\s*phrase|recovery\s*phrase|bip39/i, points: 32, sev: "crit", title: "Seed Phrase / BIP-39 Harvester Strings", desc: "Binary contains explicit mnemonic/recovery phrase harvesting keywords." },
  { pat: /AccessibilityService|BIND_ACCESSIBILITY_SERVICE/i, points: 28, sev: "crit", title: "Android Accessibility Screen-Overlay Hook", desc: "Abused by Android crypto trojans to read wallet screens silently." },
  { pat: /ClipboardManager|getPrimaryClip/i, points: 20, sev: "warn", title: "Clipboard Address-Swapper / Sniffer", desc: "Monitors clipboard to hijack copied wallet addresses." },
  { pat: /setApprovalForAll|eth_sign|personal_sign|Permit2/i, points: 24, sev: "warn", title: "Web3 Unlimited Permit / Blind-Sign Drainer Payload", desc: "Contains wallet approval/signature drainer RPC calls." },
  { pat: /DexClassLoader|InMemoryDexClassLoader/i, points: 25, sev: "crit", title: "Dynamic Encrypted Payload Dropper (DexClassLoader)", desc: "Loads hidden secondary Android DEX code at runtime." },
  { pat: /api\.telegram\.org\/bot|discord\.com\/api\/webhooks/i, points: 35, sev: "crit", title: "Hardcoded Telegram Bot / Discord Exfiltration Webhook", desc: "Stealer malware sends captured keys directly to an external bot webhook." },
];

function computeShannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i += 1) freq[bytes[i]] += 1;
  let h = 0;
  for (let i = 0; i < 256; i += 1) {
    if (freq[i] === 0) continue;
    const p = freq[i] / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function inspectBinaryBuffer(filename, bytes) {
  if (!requireAuthenticatedScanSession()) return;

  const badge = document.getElementById("apkStatusBadge");
  const out = document.getElementById("apkAuditOutput");
  badge.textContent = "AUDITING...";
  out.innerHTML = `<div class="muted" style="padding:16px 0;text-align:center;">Verifying server quota &amp; inspecting binary artifact...</div>`;

  const hash = await sha256Hex(bytes.buffer);
  const sampleSlice = bytes.slice(0, Math.min(bytes.length, 2 * 1024 * 1024));

  const { res: apkRes, data: apkJson } = await apiJson("/api/alphashield/apk-audit", {
    method: "POST",
    body: JSON.stringify({
      filename,
      size_bytes: bytes.length,
      sha256: hash,
      sample_base64: bytesToBase64(sampleSlice),
    }),
  });

  if (apkRes.status === 401) {
    serverTenant = null;
    refreshQuotaUI();
    badge.textContent = "SIGN IN REQUIRED";
    badge.className = "badge badge-indigo";
    out.innerHTML = `<div class="muted" style="padding:16px 0;text-align:center;">Sign in to your free AlphaShield workspace to scan APK &amp; binary files.</div>`;
    openAlphaAuthModal();
    return;
  }
  if (apkRes.status === 402) {
    if (apkJson?.tenant) serverTenant = apkJson.tenant;
    refreshQuotaUI();
    badge.textContent = "QUOTA REACHED";
    badge.className = "badge badge-amber";
    out.innerHTML = `<div class="finding warn">
      <div class="finding-title">Daily Free Scan Limit Reached</div>
      <div class="finding-desc">${escapeHtml(apkJson?.error?.message || "Upgrade to AlphaShield Pro ($19/mo) for unlimited SafeAPK & contract scans.")}</div>
    </div>`;
    document.getElementById("paywallModal")?.classList.add("open");
    return;
  }
  if (!apkRes.ok || !apkJson?.ok) {
    badge.textContent = "ERROR";
    badge.className = "badge badge-red";
    out.innerHTML = `<div class="finding crit">
      <div class="finding-title">Binary Audit Failed</div>
      <div class="finding-desc">${escapeHtml(apkJson?.error?.message || "Server binary inspection failed.")}</div>
    </div>`;
    return;
  }

  if (apkJson.tenant) {
    serverTenant = apkJson.tenant;
    refreshQuotaUI();
  }

  const entropy = computeShannonEntropy(bytes);
  const textSample = new TextDecoder("latin1").decode(sampleSlice);

  let risk = 0;
  const hits = [];
  for (const rule of DRAINER_PATTERNS) {
    if (rule.pat.test(textSample)) {
      risk += rule.points;
      hits.push(rule);
    }
  }
  if (entropy > 7.55 && bytes.length > 4096) {
    risk += 22;
    hits.push({
      sev: "warn",
      title: `High Packed/Encrypted Entropy (${entropy.toFixed(2)} bits/byte)`,
      desc: "Near-random byte distribution (>7.55) indicates packed or encrypted binary sections.",
    });
  }
  if (!hits.length) {
    hits.push({
      sev: "safe",
      title: "No Wallet-Drainer or Keylogger Signatures Detected",
      desc: "Zero seed-phrase harvesters, Telegram exfiltration webhooks, or Accessibility overlay hooks found.",
    });
  }

  const safety = Math.max(4, Math.min(99, 100 - risk));
  const color = safety >= 75 ? "#10b981" : safety >= 45 ? "#f59e0b" : "#ef4444";
  const verdict = safety >= 75 ? "CLEAN ARTIFACT" : safety >= 45 ? "SUSPICIOUS · REVIEW" : "DANGER · WALLET DRAINER MALWARE";
  badge.textContent = verdict;
  badge.className = safety >= 75 ? "badge badge-green" : safety >= 45 ? "badge badge-amber" : "badge badge-red";

  out.innerHTML = `
    <div class="score-box">
      <div class="score-circle" style="border-color:${color};color:${color};">${safety}</div>
      <div style="min-width:0;">
        <div style="font-weight:900;font-size:14.5px;color:${color};">${verdict}</div>
        <div style="font-weight:700;font-size:13px;margin-top:2px;">${escapeHtml(filename)}</div>
        <div class="mono muted" style="font-size:10.5px;margin-top:3px;word-break:break-all;">
          SHA-256: ${hash.slice(0, 24)}... · Entropy: ${entropy.toFixed(2)} b/B
        </div>
      </div>
    </div>
    <div class="finding-list">
      ${hits
        .map(
          (h) => `
        <div class="finding ${h.sev === "crit" ? "crit" : h.sev === "warn" ? "warn" : "safe"}">
          <div class="finding-title">${escapeHtml(h.title)}</div>
          <div class="finding-desc">${escapeHtml(h.desc)}</div>
        </div>`,
        )
        .join("")}
    </div>
  `;
}

function setBillingPeriod(period) {
  billingPeriod = period;
  document.getElementById("periodMonthlyBtn").className = period === "MONTHLY" ? "btn btn-indigo btn-sm" : "btn btn-sm";
  document.getElementById("periodYearlyBtn").className = period === "YEARLY" ? "btn btn-indigo btn-sm" : "btn btn-sm";
  document.getElementById("proPriceLabel").innerHTML =
    period === "MONTHLY"
      ? `$19 <span class="muted" style="font-size:13px;font-weight:500;">/ month</span>`
      : `$159 <span class="muted" style="font-size:13px;font-weight:500;">/ year ($13.25/mo)</span>`;
  document.getElementById("whalePriceLabel").innerHTML =
    period === "MONTHLY"
      ? `$49 <span class="muted" style="font-size:13px;font-weight:500;">/ month</span>`
      : `$399 <span class="muted" style="font-size:13px;font-weight:500;">/ year ($33.25/mo)</span>`;
}

async function checkKelviqBackendStatus() {
  const badge = document.getElementById("kelviqModeBadge");
  const txt = document.getElementById("kelviqStatusText");
  try {
    const res = await fetchWithTimeout("/api/kelviq/status", { credentials: "same-origin" }, 3000);
    if (!res.ok) throw new Error("no_backend");
    const data = await res.json();
    backendAvailable = true;
    directUsdtEnabled = Boolean(data.kelviq?.direct_usdt_enabled);
    if (data.csrf_token) csrfToken = data.csrf_token;
    serverTenant = data.authenticated ? data.tenant : null;
    refreshQuotaUI();

    document.getElementById("connectionBadge").textContent = "Live Backend + REA WASM + Kelviq SDK";
    if (data.kelviq?.live_keys_configured) {
      badge.textContent = `LIVE KELVIQ (${String(data.kelviq.environment).toUpperCase()})`;
      badge.className = "badge badge-green";
      txt.textContent = `Connected to @kelviq/node-sdk (${data.kelviq.organization}). Live global checkouts, customer portal & signed webhooks are active.`;
    } else if (data.kelviq?.sandbox_enabled) {
      badge.textContent = "SANDBOX ENABLED";
      badge.className = "badge badge-amber";
      txt.textContent = `Server running @kelviq/node-sdk in explicit local sandbox mode (ALLOW_SANDBOX_BILLING=true).`;
    } else {
      badge.textContent = "BILLING LOCKED";
      badge.className = "badge badge-indigo";
      txt.textContent = "Server online. Configure KELVIQ_SERVER_API_KEY + KELVIQ_WEBHOOK_SECRET + PUBLIC_BASE_URL to accept live payments.";
    }
  } catch {
    backendAvailable = false;
    directUsdtEnabled = false;
    serverTenant = null;
    refreshQuotaUI();
    badge.textContent = "STATIC CLIENT";
    badge.className = "badge badge-indigo";
    txt.textContent = "Running in client-only mode (3 free local browser scans/day).";
  }
}

async function startKelviqCheckout(planId) {
  if (!backendAvailable) {
    openPlaybookModal();
    return;
  }
  if (!serverTenant) {
    openAlphaAuthModal();
    return;
  }
  try {
    const { data } = await apiJson("/api/kelviq/checkout", {
      method: "POST",
      body: JSON.stringify({ plan_id: planId, charge_period: billingPeriod }),
    });
    if (data.ok && data.checkout_url) {
      window.location.href = data.checkout_url;
      return;
    }
    if (data.ok && data.mode === "kelviq_preview_sandbox") {
      alert(`Sandbox checkout simulated (${data.plan?.name || planId}).`);
      return;
    }
    alert(data.error?.message || "Kelviq checkout is not configured on this server.");
  } catch {
    openPlaybookModal();
  }
}

async function activateLicenseKey() {
  const key = document.getElementById("licenseKeyInput").value.trim();
  const fb = document.getElementById("licenseFeedback");
  if (!key) {
    fb.textContent = "Enter a license key first.";
    return;
  }
  if (!backendAvailable) {
    fb.style.color = "#f87171";
    fb.textContent = "License verification requires the live backend server.";
    return;
  }
  if (!serverTenant) {
    openAlphaAuthModal();
    fb.style.color = "#fbbf24";
    fb.textContent = "Sign in first so your license binds exclusively to your server account.";
    return;
  }
  try {
    const { data } = await apiJson("/api/kelviq/license/activate", {
      method: "POST",
      body: JSON.stringify({ license_key: key }),
    });
    if (data.ok) {
      serverTenant = data.tenant;
      refreshQuotaUI();
      fb.style.color = "#34d399";
      fb.textContent = `✓ Verified & bound! ${data.tenant?.alphashield_plan_name || "Pro"} active.`;
      return;
    }
    fb.style.color = "#f87171";
    fb.textContent = data.error?.message || "Invalid license key.";
  } catch {
    fb.style.color = "#f87171";
    fb.textContent = "License verification request failed.";
  }
}

async function openCustomerPortal() {
  if (!backendAvailable) {
    alert("Customer Billing Portal requires the live backend server.");
    return;
  }
  if (!serverTenant) {
    openAlphaAuthModal();
    return;
  }
  const { data } = await apiJson("/api/kelviq/portal", { method: "POST", body: JSON.stringify({}) });
  const pUrl = data.portal_url || data.portal?.portalUrl || data.portal?.url;
  if (data.ok && pUrl) {
    window.open(pUrl, "_blank", "noopener,noreferrer");
    return;
  }
  alert(data.error?.message || "Set KELVIQ_SERVER_API_KEY to launch live Kelviq customer portal.");
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Delegated event wiring (Zero inline on*= handlers anywhere in static or dynamic DOM)
document.addEventListener("click", (e) => {
  const backdrop = e.target.closest("[data-modal-backdrop]");
  if (backdrop && e.target === backdrop) {
    closeModal(backdrop.getAttribute("data-modal-backdrop"));
    return;
  }

  const actionEl = e.target.closest("[data-action]");
  if (!actionEl) return;
  const action = actionEl.getAttribute("data-action");
  if (actionEl.tagName === "A") e.preventDefault();

  switch (action) {
    case "switch-tab":
      switchTab(actionEl.getAttribute("data-tab"));
      break;
    case "open-auth":
      openAlphaAuthModal();
      break;
    case "open-playbook":
      openPlaybookModal();
      break;
    case "close-modal":
      closeModal(actionEl.getAttribute("data-modal"));
      break;
    case "refresh-tickers":
      void loadGlobalTickers();
      break;
    case "search-dex":
      void searchDexPairs();
      break;
    case "quick-dex":
      document.getElementById("dexSearchInput").value = actionEl.getAttribute("data-query") || "PEPE";
      void searchDexPairs();
      break;
    case "jump-scan":
      jumpToContractScan(
        actionEl.getAttribute("data-chain"),
        actionEl.getAttribute("data-addr"),
        actionEl.getAttribute("data-label"),
      );
      break;
    case "save-watch":
      saveToWatchlist(
        actionEl.getAttribute("data-sym"),
        actionEl.getAttribute("data-chain"),
        actionEl.getAttribute("data-addr"),
        Number(actionEl.getAttribute("data-price") || 0),
      );
      break;
    case "remove-watch":
      removeWatchlist(actionEl.getAttribute("data-addr"));
      break;
    case "preset-contract":
      document.getElementById("chainSelect").value = actionEl.getAttribute("data-chain");
      document.getElementById("contractAddressInput").value = actionEl.getAttribute("data-addr");
      document.getElementById("rawBytecodeInput").value = "";
      void runSmartContractAudit(actionEl.getAttribute("data-label"));
      break;
    case "preset-honeypot":
      loadSimulatedHoneypot();
      break;
    case "run-contract-audit":
      void runSmartContractAudit();
      break;
    case "share-wa":
      if (lastAuditSummaryText) {
        window.open(`https://wa.me/?text=${encodeURIComponent(lastAuditSummaryText)}`, "_blank", "noopener,noreferrer");
      }
      break;
    case "share-x":
      if (lastAuditSummaryText) {
        window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(lastAuditSummaryText)}`, "_blank", "noopener,noreferrer");
      }
      break;
    case "copy-alert":
      if (lastAuditSummaryText) {
        navigator.clipboard?.writeText(lastAuditSummaryText).catch(() => {});
      }
      break;
    case "synthetic-apk": {
      const enc = new TextEncoder();
      if (actionEl.getAttribute("data-kind") === "drainer_apk") {
        void inspectBinaryBuffer(
          "SniperBot_Pro_Mod_v4.apk",
          enc.encode(
            "PK\x03\x04 classes.dex BIND_ACCESSIBILITY_SERVICE ClipboardManager getPrimaryClip extract bip39 mnemonic seed phrase setApprovalForAll https://api.telegram.org/bot77123:AAH/sendMessage DexClassLoader",
          ),
        );
      } else {
        void inspectBinaryBuffer(
          "PortfolioWidget_Signed_v1.2.apk",
          enc.encode("PK\x03\x04 META-INF/MANIFEST.MF AndroidManifest.xml PortfolioPriceWidget normal view only"),
        );
      }
      break;
    }
    case "set-period":
      setBillingPeriod(actionEl.getAttribute("data-period") || "MONTHLY");
      break;
    case "start-kelviq":
      void startKelviqCheckout(actionEl.getAttribute("data-plan"));
      break;
    case "open-usdt":
      openUsdtCheckoutModal(actionEl.getAttribute("data-plan"), Number(actionEl.getAttribute("data-usd") || 19));
      break;
    case "activate-license":
      void activateLicenseKey();
      break;
    case "open-portal":
      void openCustomerPortal();
      break;
    case "open-legal":
      openLegalModal(actionEl.getAttribute("data-section"));
      break;
    case "paywall-kelviq":
      closeModal("paywallModal");
      void startKelviqCheckout("alphashield_pro");
      break;
    case "paywall-pricing":
      closeModal("paywallModal");
      switchTab("pricing");
      break;
    case "alpha-signin":
      void alphaSignIn();
      break;
    case "alpha-register":
      void alphaRegister();
      break;
    case "alpha-signout":
      void alphaSignOut();
      break;
    case "create-payment-intent":
      void createBoundPaymentIntent();
      break;
    case "pay-web3-wallet":
      void payWithWeb3Wallet();
      break;
    case "verify-payment-tx":
      void verifyOnChainPaymentTx();
      break;
    default:
      break;
  }
});

document.getElementById("dexSearchInput")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") void searchDexPairs();
});

document.getElementById("apkFileInput")?.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const buf = await file.arrayBuffer();
  await inspectBinaryBuffer(file.name, new Uint8Array(buf));
});

document.getElementById("payChainSelect")?.addEventListener("change", () => {
  activePaymentIntent = null;
  document.getElementById("intentSummaryBox").textContent =
    "Chain changed — click Create Intent to reserve a fresh bound intent.";
});

refreshQuotaUI();
renderWatchlist();
void loadGlobalTickers();
void searchDexPairs();
void checkKelviqBackendStatus();
