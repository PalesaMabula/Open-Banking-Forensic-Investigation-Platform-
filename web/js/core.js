// ================================================
// Global application state
// ================================================
const state = {
  currentFindingId: null,
  findings: [],
  lastCustomerAccountId: null,
  lastAppAccountId: { BudgetWise: null, InsureWise: null },
  activeAccountId: null,
  pendingInvestigationFindingId: null,
};

const investigatorState = { session: null, investigator: null };
let currentWorkspace = null;

function setActiveAccount(accountId) {
  state.activeAccountId = accountId;
  const el = document.getElementById("scenario-active-account");
  if (el) el.textContent = accountId || "No active account";
}

// ================================================
// Core API request helper (fetch wrapper, error handling, investigator auth headers)
// ================================================
function investigatorHeaders() {
  return investigatorState.session
    ? { "X-Investigator-Session": investigatorState.session }
    : {};
}
async function apiRequest(path, options = {}) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {},
  );
  let response;
  try {
    response = await fetch(path, Object.assign({}, options, { headers }));
  } catch (err) {
    throw new Error("Network error — could not reach the platform.");
  }
  let body = null;
  try {
    body = await response.json();
  } catch (e) {}
  if (!response.ok) throw new Error(friendlyError(response.status, body));
  return body;
}

function friendlyError(status, body) {
  const detail = body && body.detail ? body.detail : null;
  if (status === 401) return detail || "Authentication required.";
  if (status === 403) return detail || "Consent does not allow this operation.";
  if (status === 404) return detail || "Resource not found.";
  return detail || `Request failed (${status}).`;
}

// ================================================
// Shared formatting, labeling, and small presentational helpers
// ================================================
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString() + " (UTC: " + iso + ")";
  } catch (e) {
    return iso;
  }
}

function shortHash(hash) {
  if (!hash) return "—";
  if (hash.length <= 16) return hash;
  return hash.slice(0, 10) + "..." + hash.slice(-8);
}

function maskAccount(accountId) {
  if (!accountId || accountId.length <= 4) return accountId || "—";
  return "••••" + accountId.slice(-4);
}

function badge(text, className) {
  return `<span class="badge badge-${className}">${escapeHtml(text)}</span>`;
}

function humanizeEventType(eventType) {
  if (!eventType) return "";
  return eventType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const EMPHASIS_EVENT_TYPES = new Set([
  "TOKEN_ISSUED",
  "CONSENT_PERMISSION_DENIED",
  "TOKEN_HIJACKING_DETECTED",
  "CONSENT_BASED_FRAUD_DETECTED",
  "CROSS_BORDER_EXFILTRATION_DETECTED",
  "CREDENTIAL_THEFT_DETECTED",
]);

const PERMISSION_LABELS = {
  accounts: "Account Information",
  transactions: "Transaction History",
};
function permLabel(p) {
  return PERMISSION_LABELS[p] || humanizeEventType(p);
}

const CUSTODY_ACTOR_LABELS = {
  OBFIR_SYSTEM: "Open Banking Forensic System",
  OBFIR_EVIDENCE_STORE: "Forensic Evidence Store",
};
function custodyActorLabel(actor) {
  return CUSTODY_ACTOR_LABELS[actor] || actor;
}

const CUSTODY_ACTION_LABELS = {
  CREATED: "Created",
  ACCESSED: "Accessed",
  ANALYSED: "Analysed",
  VERIFIED: "Verified",
  EXPORTED: "Exported",
  TRANSFERRED: "Transferred",
};
function custodyActionLabel(action) {
  return CUSTODY_ACTION_LABELS[action] || action;
}

function metricCard(label, value, valueClass) {
  return `<div class="metric-card">
    <div class="label">${escapeHtml(label)}</div>
    <div class="value ${valueClass || ""}">${escapeHtml(String(value))}</div>
  </div>`;
}

function toggleWarning(elId, show, text) {
  const el = document.getElementById(elId);
  if (show) {
    el.textContent = text;
    el.classList.remove("hidden");
  } else {
    el.classList.add("hidden");
  }
}

// ================================================
// Theme (light/dark) toggle
// ================================================
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("obfir-theme", theme);
  const btn = document.getElementById("theme-toggle-btn");
  if (btn) btn.textContent = theme === "dark" ? "Light" : "Dark";
}

function initTheme() {
  const saved = localStorage.getItem("obfir-theme") || "light";
  applyTheme(saved);
  const btn = document.getElementById("theme-toggle-btn");
  if (btn) {
    btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }
}
// ================================================
// Workspace switching (Open Banking Simulation / Forensic Investigation) and sidebar navigation
// ================================================
function showHomeScreen() {
  currentWorkspace = null;
  document.getElementById("home-screen").classList.remove("hidden");
  document.getElementById("investigator-bar").classList.add("hidden");
  document.getElementById("app-shell").classList.add("hidden");
}

function setNavGroupVisibility(workspace) {
  document
    .getElementById("nav-group-openbanking")
    .classList.toggle("hidden", workspace !== "openbanking");
  document
    .getElementById("nav-group-forensics")
    .classList.toggle("hidden", workspace !== "forensics");
  document
    .getElementById("return-home-btn")
    .classList.toggle("hidden", workspace !== "openbanking");
}

function activateSection(sectionName) {
  document
    .querySelectorAll(".nav-item")
    .forEach((b) => b.classList.remove("active"));
  document
    .querySelectorAll(".section")
    .forEach((s) => s.classList.remove("active"));
  const navBtn = document.querySelector(
    `.nav-item[data-section="${sectionName}"]`,
  );
  if (navBtn) navBtn.classList.add("active");
  const sectionEl = document.getElementById("section-" + sectionName);
  if (sectionEl) sectionEl.classList.add("active");
}

function enterOpenBankingWorkspace() {
  currentWorkspace = "openbanking";
  document.getElementById("home-screen").classList.add("hidden");
  document.getElementById("investigator-bar").classList.add("hidden");
  document.getElementById("app-shell").classList.remove("hidden");
  setNavGroupVisibility("openbanking");
  activateSection("customer");
}

function enterForensicWorkspace() {
  currentWorkspace = "forensics";
  document.getElementById("home-screen").classList.add("hidden");
  document.getElementById("investigator-bar").classList.remove("hidden");
  document.getElementById("app-shell").classList.remove("hidden");
  setNavGroupVisibility("forensics");
  activateSection("dashboard");
}

function initNav() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".nav-item")
        .forEach((b) => b.classList.remove("active"));
      document
        .querySelectorAll(".section")
        .forEach((s) => s.classList.remove("active"));
      btn.classList.add("active");
      document
        .getElementById("section-" + btn.dataset.section)
        .classList.add("active");
    });
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".tab-btn")
        .forEach((b) => b.classList.remove("active"));
      document
        .querySelectorAll(".tab-panel")
        .forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    });
  });

  document.getElementById("refresh-btn").addEventListener("click", refreshAll);
  document
    .getElementById("return-home-btn")
    .addEventListener("click", showHomeScreen);
}

function goToInvestigation(findingId) {
  state.currentFindingId = findingId;
  activateSection("investigation");
  loadInvestigation(findingId);
}