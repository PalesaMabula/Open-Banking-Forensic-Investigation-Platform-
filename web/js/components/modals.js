// ================================================
// Scenario Controls modal and hash-detail modal
// ================================================
function showHashModal(fullHash) {
  const modal = document.getElementById("scenario-modal");
  document.getElementById("scenario-modal-title").textContent = "Full Hash";
  document.getElementById("scenario-modal-body").innerHTML =
    `<div class="hash-cell" style="word-break:break-all;">${escapeHtml(fullHash)}</div>`;
  document.getElementById("scenario-modal-explanation").textContent = "";
  document.getElementById("scenario-modal-extra").innerHTML = "";
  document.getElementById("scenario-modal-run").classList.add("hidden");
  document.getElementById("scenario-modal-cancel").textContent = "Close";
  modal.classList.remove("hidden");
}

const SCENARIO_DEFS = {
  "credential-theft": {
    title: "Credential Theft",
    explanation: (app) =>
      `Valid ${app} credentials will be used from a new simulated context to request a new access token, scoped to the active account.`,
    endpoint: (app) => `/scenarios/credential-theft/${app}`,
  },
  "token-hijacking": {
    title: "Token Hijacking",
    explanation: (app) =>
      `The same active ${app} session token will be replayed from another simulated context, scoped to the active account.`,
    endpoint: (app) => `/scenarios/token-hijacking/${app}`,
  },
  "consent-fraud": {
    title: "Consent-Based Fraud",
    explanation: (app) =>
      `${app} will attempt to access data for the active account beyond what Customer 001 has authorized.`,
    endpoint: (app) => `/scenarios/consent-fraud/${app}`,
  },
  "cross-border": {
    title: "Cross-Border Data Exfiltration",
    explanation: (app) =>
      `A successful, authorized ${app} access to the active account will be associated with simulated foreign destination metadata.`,
    endpoint: (app) => `/scenarios/cross-border/${app}`,
  },
};

function initScenarioButtons() {
  document.querySelectorAll(".btn-scenario").forEach((btn) => {
    btn.addEventListener("click", () =>
      openScenarioModal(btn.dataset.scenario),
    );
  });
  document
    .getElementById("scenario-modal-cancel")
    .addEventListener("click", closeScenarioModal);
}

function closeScenarioModal() {
  document.getElementById("scenario-modal").classList.add("hidden");
  document.getElementById("scenario-modal-run").classList.remove("hidden");
  document.getElementById("scenario-modal-cancel").textContent = "Cancel";
}

function openScenarioModal(scenarioKey) {
  if (!state.activeAccountId) {
    const resultEl = document.getElementById("scenario-result");
    resultEl.classList.remove("hidden");
    resultEl.innerHTML =
      '<div class="warning-banner">No active account. Load a customer account (Customer page) or connect an application to an account before running a controlled incident simulation.</div>';
    return;
  }

  const def = SCENARIO_DEFS[scenarioKey];
  const modal = document.getElementById("scenario-modal");
  const selectedApp = document.getElementById("scenario-app-select").value;

  document.getElementById("scenario-modal-title").textContent = def.title;
  document.getElementById("scenario-modal-body").innerHTML = `
    <div><div class="kv-label">Customer</div><div class="kv-value">Customer 001</div></div>
    <div><div class="kv-label">Active Account</div><div class="kv-value hash-cell">${escapeHtml(state.activeAccountId)}</div></div>
    <div><div class="kv-label">Application</div><div class="kv-value">${escapeHtml(selectedApp)}</div></div>
  `;
  document.getElementById("scenario-modal-explanation").textContent =
    def.explanation(selectedApp);
  document.getElementById("scenario-modal-extra").innerHTML = "";

  const runBtn = document.getElementById("scenario-modal-run");
  runBtn.classList.remove("hidden");
  runBtn.onclick = () => runScenarioFromModal(def, scenarioKey);

  modal.classList.remove("hidden");
}

async function runScenarioFromModal(def, scenarioKey) {
  const resultEl = document.getElementById("scenario-result");
  const selectedApp = document.getElementById("scenario-app-select").value;
  const accountId = state.activeAccountId;

  closeScenarioModal();
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = '<div class="loading-text">Running simulation...</div>';

  try {
    const path = def.endpoint(selectedApp);
    const result = await apiRequest(path, {
      method: "POST",
      body: JSON.stringify({ account_id: accountId }),
    });
    renderScenarioResult(def.title, selectedApp, accountId, result);
    loadFindings();
    loadDashboard();
  } catch (err) {
    resultEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

function renderScenarioResult(title, appName, accountId, result) {
  const resultEl = document.getElementById("scenario-result");
  resultEl.innerHTML = `
    <h3 style="margin-top:0;">Incident Simulated</h3>
    <div class="kv-grid">
      <div><div class="kv-label">Scenario</div><div class="kv-value">${escapeHtml(title)}</div></div>
      <div><div class="kv-label">Application</div><div class="kv-value">${escapeHtml(appName)}</div></div>
      <div><div class="kv-label">Customer</div><div class="kv-value">Customer 001</div></div>
      <div><div class="kv-label">Account</div><div class="kv-value hash-cell">${escapeHtml(accountId)}</div></div>
      <div><div class="kv-label">Executed</div><div class="kv-value">${result.executed ? "Yes" : "No"}</div></div>
      <div><div class="kv-label">Detection</div><div class="kv-value">${result.detected ? badge("DETECTED", "invalid") : badge("NOT DETECTED", "valid")}</div></div>
      <div><div class="kv-label">Finding</div><div class="kv-value hash-cell">${result.finding_id ? shortHash(result.finding_id) : "—"}</div></div>
    </div>
    ${result.detail ? `<p style="margin-top:10px; color: var(--muted); font-size:13px;">${escapeHtml(result.detail)}</p>` : ""}
    ${result.finding_id ? `<button class="btn btn-primary" style="margin-top:10px;" id="investigate-scenario-finding">Investigate Finding</button>` : ""}
    <details style="margin-top:12px;"><summary style="cursor:pointer; font-size:13px; color:var(--accent-dark);">Technical Response</summary>
      <pre style="white-space:pre-wrap; font-size:12px; background:var(--surface-alt); padding:10px; border-radius:4px;">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
    </details>
  `;
  if (result.finding_id) {
    document
      .getElementById("investigate-scenario-finding")
      .addEventListener("click", () => {
        if (investigatorState.investigator) {
          enterForensicWorkspace();
          goToInvestigation(result.finding_id);
          return;
        }
        state.pendingInvestigationFindingId = result.finding_id;
        document.getElementById("investigator-login-error").textContent =
          "Sign in as an investigator to view this finding.";
        document
          .getElementById("investigator-login-modal")
          .classList.remove("hidden");
      });
  }
}