// ================================================
// API Communication, Findings, Investigation, Evaluation pages
// ================================================
async function loadApiCommunication() {
  const el = document.getElementById("api-comm-table");
  el.innerHTML = '<div class="loading-text">Loading API communication...</div>';
  try {
    const [interactions, events] = await Promise.all([
      apiRequest("/forensics/interactions"),
      apiRequest("/forensics/events"),
    ]);

    const eventsByInteraction = {};
    events.forEach((e) => {
      if (e.interaction_id) {
        eventsByInteraction[e.interaction_id] =
          eventsByInteraction[e.interaction_id] || [];
        eventsByInteraction[e.interaction_id].push(e);
      }
    });

    const resourceLabels = { "/banking/accounts": "Account Information" };

    const rows = interactions.slice(0, 100).map((interaction) => {
      const linked = eventsByInteraction[interaction.interaction_id] || [];
      let applicationId = null,
        decision = "Allowed",
        resource = interaction.endpoint;

      linked.forEach((e) => {
        let details = {};
        try {
          details = JSON.parse(e.details_json || "{}");
        } catch (err) {}
        if (details.application_id) applicationId = details.application_id;
        if (e.event_type === "CONSENT_PERMISSION_DENIED") decision = "Denied";
        if (details.resource === "transactions")
          resource = "Transaction History";
        if (details.resource === "accounts") resource = "Account Information";
      });

      if (resourceLabels[interaction.endpoint])
        resource = resourceLabels[interaction.endpoint];

      return { interaction, applicationId, resource, decision };
    });

    if (!rows.length) {
      el.innerHTML =
        '<div class="empty-state">No API communication captured yet.</div>';
      return;
    }

    const ob = await apiRequest("/open-banking/summary").catch(() => ({
      applications: [],
    }));
    const appsById = {};
    ob.applications.forEach((a) => {
      appsById[a.application_id] = a.application_name;
    });

    el.innerHTML = `<table>
      <thead><tr><th>Time</th><th>Application</th><th>Action</th><th>Resource</th><th>Decision</th><th>HTTP Status</th></tr></thead>
      <tbody>${rows
        .map(
          (r) => `<tr>
        <td>${formatTimestamp(r.interaction.timestamp)}</td>
        <td>${escapeHtml(r.applicationId ? appsById[r.applicationId] || "—" : "—")}</td>
        <td>${escapeHtml(r.interaction.http_method)}</td>
        <td>${escapeHtml(r.resource)}</td>
        <td>${badge(r.decision, r.decision)}</td>
        <td>${escapeHtml(r.interaction.response_status)}</td>
      </tr>`,
        )
        .join("")}</tbody>
    </table>`;
  } catch (err) {
    el.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}
let cachedApplications = [];

async function loadFindings() {
  const wrap = document.getElementById("findings-table-wrap");
  wrap.innerHTML = '<div class="loading-text">Loading findings...</div>';
  try {
    state.findings = await apiRequest("/forensics/findings");
    try {
      const ob = await apiRequest("/open-banking/summary");
      cachedApplications = ob.applications;
    } catch (e) {
      /* fall back to IDs */
    }
    renderFindingsTable();
  } catch (err) {
    wrap.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

function appNameFor(applicationId) {
  const app = cachedApplications.find(
    (a) => a.application_id === applicationId,
  );
  return app
    ? app.application_name
    : applicationId
      ? shortHash(applicationId)
      : "—";
}

function renderFindingsTable() {
  const wrap = document.getElementById("findings-table-wrap");
  const scenarioFilter = document.getElementById("filter-scenario").value;
  const severityFilter = document.getElementById("filter-severity").value;
  const statusFilter = document.getElementById("filter-status").value;

  let rows = state.findings.filter(
    (f) =>
      (!scenarioFilter || f.scenario_type === scenarioFilter) &&
      (!severityFilter || f.severity === severityFilter) &&
      (!statusFilter || f.status === statusFilter),
  );

  if (rows.length === 0) {
    wrap.innerHTML =
      '<div class="empty-state">No findings have been detected yet.</div>';
    return;
  }

  wrap.innerHTML = `<table>
    <thead><tr><th>Scenario</th><th>Severity</th><th>Status</th><th>Detected At</th><th>Application</th><th>Account</th><th></th></tr></thead>
    <tbody>${rows
      .map(
        (f) => `<tr>
      <td>${humanizeEventType(f.scenario_type)}</td>
      <td>${badge(f.severity, f.severity)}</td>
      <td>${badge(f.status, f.status)}</td>
      <td>${formatTimestamp(f.detected_at)}</td>
      <td>${escapeHtml(appNameFor(f.application_id))}</td>
      <td>${escapeHtml(f.account_id || "—")}</td>
      <td>
        <button class="btn btn-small" data-investigate="${f.finding_id}">Investigate</button>
        <button class="btn btn-small" data-create-case="${f.finding_id}|${f.account_id || ""}">Create Case</button>
      </td>
    </tr>`,
      )
      .join("")}</tbody>
  </table>`;

  wrap.querySelectorAll("[data-investigate]").forEach((btn) => {
    btn.addEventListener("click", () =>
      goToInvestigation(btn.dataset.investigate),
    );
  });
  wrap.querySelectorAll("[data-create-case]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const [findingId, accountId] = btn.dataset.createCase.split("|");
      activateSection("cases");
      document.getElementById("case-finding-id").value = findingId;
      document.getElementById("case-account-id").value = accountId;
      document.getElementById("case-title").focus();
    });
  });
}
async function loadInvestigation(findingId) {
  document.getElementById("investigation-empty").classList.add("hidden");
  document.getElementById("investigation-content").classList.remove("hidden");
  const summaryPanel = document.getElementById("investigation-summary-panel");
  summaryPanel.innerHTML =
    '<div class="loading-text">Loading investigation summary...</div>';

  try {
    const summary = await apiRequest(`/forensics/investigations/${findingId}`);
    renderInvestigationSummary(summary);
  } catch (err) {
    summaryPanel.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  if (investigatorState.investigator) {
    try {
      await apiRequest(`/forensics/investigations/${findingId}/auto-access`, {
        method: "POST",
        headers: investigatorHeaders(),
      });
    } catch (e) {
      /* non-fatal — evidence remains viewable even if this fails */
    }
  }

  loadTimeline(findingId);
  loadEvidence(findingId);
  loadCustody(findingId);
}

function renderInvestigationSummary(summary) {
  const panel = document.getElementById("investigation-summary-panel");
  const app = summary.application ? summary.application.application_name : "—";
  const evidenceOk = summary.evidence_integrity === "VALID";
  const custodyOk = summary.custody_integrity === "VALID";
  const maskedAccount = summary.account_id
    ? maskAccount(summary.account_id)
    : "—";
  const customerLabel = summary.customer_id
    ? summary.customer_id === "customer-001"
      ? "Customer 001"
      : escapeHtml(summary.customer_id)
    : "—";

  panel.innerHTML = `
    <div class="kv-grid">
      <div><div class="kv-label">Scenario</div><div class="kv-value">${humanizeEventType(summary.scenario_type)}</div></div>
      <div><div class="kv-label">Severity</div><div class="kv-value">${badge(summary.severity, summary.severity)}</div></div>
      <div><div class="kv-label">Status</div><div class="kv-value">${badge(summary.status, summary.status)}</div></div>
      <div><div class="kv-label">Detected At</div><div class="kv-value">${formatTimestamp(summary.detected_at)}</div></div>
      <div><div class="kv-label">Application</div><div class="kv-value">${escapeHtml(app)}</div></div>
      <div><div class="kv-label">Customer</div><div class="kv-value">${customerLabel}</div></div>
      <div><div class="kv-label">Account</div><div class="kv-value hash-cell">${escapeHtml(maskedAccount)}</div></div>
      <div><div class="kv-label">Evidence Count</div><div class="kv-value">${summary.evidence_count}</div></div>
      <div><div class="kv-label">Evidence Integrity</div><div class="kv-value">${badge(summary.evidence_integrity, evidenceOk ? "valid" : "invalid")}</div></div>
      <div><div class="kv-label">Custody Integrity</div><div class="kv-value">${badge(summary.custody_integrity, custodyOk ? "valid" : "invalid")}</div></div>
    </div>

    <div class="panel" style="margin-top:16px; background:var(--surface-alt);">
      <h4 style="margin-top:0;">Incident Summary</h4>
      <p style="margin:0; font-size:14px; line-height:1.6;">${escapeHtml(summary.incident_summary || summary.description || "")}</p>
    </div>

    <details style="margin-top:14px;"><summary style="cursor:pointer; font-size:13px; color:var(--accent-dark);">Technical Details</summary>
      <div class="kv-grid" style="margin-top:10px;">
        <div><div class="kv-label">Finding ID</div><div class="kv-value hash-cell">${escapeHtml(summary.finding_id)}</div></div>
        <div><div class="kv-label">Full Account ID</div><div class="kv-value hash-cell">${escapeHtml(summary.account_id || "—")}</div></div>
        <div><div class="kv-label">Customer ID</div><div class="kv-value hash-cell">${escapeHtml(summary.customer_id || "—")}</div></div>
        <div><div class="kv-label">Consent ID</div><div class="kv-value hash-cell">${escapeHtml(summary.consent ? summary.consent.consent_id : "—")}</div></div>
        <div><div class="kv-label">Token Fingerprint</div><div class="kv-value hash-cell">${escapeHtml(summary.token_fingerprint || "—")}</div></div>
        <div><div class="kv-label">Exact Detected At (UTC)</div><div class="kv-value hash-cell">${escapeHtml(summary.detected_at)}</div></div>
      </div>
    </details>

    <div class="form-grid" style="margin-top:16px; max-width:280px;">
      <label>Update Status
        <select id="status-select">
          <option value="OPEN" ${summary.status === "OPEN" ? "selected" : ""}>Open</option>
          <option value="REVIEWED" ${summary.status === "REVIEWED" ? "selected" : ""}>Reviewed</option>
          <option value="CLOSED" ${summary.status === "CLOSED" ? "selected" : ""}>Closed</option>
        </select>
      </label>
      <button id="status-update-btn" class="btn btn-primary">Update Status</button>
      <div id="status-update-result" class="result-text"></div>
    </div>
  `;

  document
    .getElementById("status-update-btn")
    .addEventListener("click", async () => {
      const newStatus = document.getElementById("status-select").value;
      const resultEl = document.getElementById("status-update-result");
      try {
        await apiRequest(`/forensics/findings/${summary.finding_id}/status`, {
          method: "PATCH",
          body: JSON.stringify({
            status: newStatus,
            actor: "INVESTIGATOR_001",
          }),
        });
        resultEl.textContent = "Status updated.";
        resultEl.className = "result-text success";
        loadInvestigation(summary.finding_id);
        loadFindings();
        loadDashboard();
      } catch (err) {
        resultEl.textContent = err.message;
        resultEl.className = "result-text error";
      }
    });
}

async function loadTimeline(findingId) {
  const el = document.getElementById("timeline-content");
  el.innerHTML = '<div class="loading-text">Loading timeline...</div>';
  try {
    const timeline = await apiRequest(
      `/forensics/investigations/${findingId}/timeline`,
    );
    if (!timeline.length) {
      el.innerHTML =
        '<div class="empty-state">No timeline events available.</div>';
      return;
    }

    const narrativeItems = timeline.filter(
      (item) => item.category !== "CUSTODY",
    );
    const custodyCount = timeline.length - narrativeItems.length;

    el.innerHTML = `<ul class="timeline">${narrativeItems
      .map(
        (item) => `
      <li class="timeline-item ${EMPHASIS_EVENT_TYPES.has(item.event_type) ? "emphasis" : ""}">
        <div class="timeline-meta">
          <span class="timeline-category">${escapeHtml(item.category)}</span> · ${formatTimestamp(item.timestamp)}
          ${item.response_status ? " · HTTP " + item.response_status : ""}
        </div>
        <div class="timeline-desc">${escapeHtml(item.description)}</div>
      </li>`,
      )
      .join("")}</ul>
      ${custodyCount ? `<p style="font-size:12px; color:var(--muted); margin-top:8px;">${custodyCount} evidence preservation record(s) not shown here — see the Chain of Custody tab.</p>` : ""}
    `;
  } catch (err) {
    el.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

async function loadEvidence(findingId) {
  const el = document.getElementById("evidence-content");
  el.innerHTML = '<div class="loading-text">Loading evidence...</div>';
  try {
    const evidence = await apiRequest(
      `/forensics/investigations/${findingId}/evidence`,
    );
    if (!evidence.length) {
      el.innerHTML =
        '<div class="empty-state">No related evidence found.</div>';
      return;
    }
    el.innerHTML = evidence
      .map((item) => {
        if (item.status === "MISSING") {
          return `<div class="panel"><strong>${escapeHtml(item.event_id)}</strong> — ${badge("MISSING", "invalid")}</div>`;
        }
        const ok = item.integrity_status === "VALID";
        return `<div class="panel">
        <div class="kv-grid">
          <div><div class="kv-label">Event Type</div><div class="kv-value">${humanizeEventType(item.event_type)}</div></div>
          <div><div class="kv-label">Timestamp</div><div class="kv-value">${formatTimestamp(item.timestamp)}</div></div>
          <div><div class="kv-label">Account</div><div class="kv-value">${escapeHtml(item.account_id || "—")}</div></div>
          <div><div class="kv-label">Integrity</div><div class="kv-value">${badge(item.integrity_status, ok ? "valid" : "invalid")}</div></div>
          <div><div class="kv-label">Custody Records</div><div class="kv-value">${item.custody_event_count}</div></div>
        </div>
        <div style="margin-top:10px;"><div class="kv-label">Event Hash</div>
          <div class="hash-cell">${shortHash(item.event_hash)}<button class="hash-toggle" data-full="${escapeHtml(item.event_hash || "")}">Show Full</button></div></div>
        <div style="margin-top:6px;"><div class="kv-label">Previous Hash</div>
          <div class="hash-cell">${shortHash(item.previous_hash)}<button class="hash-toggle" data-full="${escapeHtml(item.previous_hash || "")}">Show Full</button></div></div>
        <details style="margin-top:10px;"><summary style="cursor:pointer; font-size:13px; color: var(--accent-dark);">View Metadata</summary>
          <pre style="white-space:pre-wrap; font-size:12px; background:var(--surface-alt); padding:10px; border-radius:4px;">${escapeHtml(JSON.stringify(item.details || {}, null, 2))}</pre>
        </details>
        <div class="app-actions" style="margin-top:12px;">
          <button class="btn btn-small" data-evidence-verify="${item.event_id}" ${investigatorState.investigator ? "" : "disabled"}>Verify Evidence</button>
          <button class="btn btn-small" data-evidence-analyse="${item.event_id}" ${investigatorState.investigator ? "" : "disabled"}>Mark as Analysed</button>
        </div>
        <div id="evidence-action-result-${item.event_id}" class="result-text"></div>
      </div>`;
      })
      .join("");

    el.querySelectorAll(".hash-toggle").forEach((btn) => {
      btn.addEventListener("click", () =>
        showHashModal(btn.dataset.full || "(empty)"),
      );
    });
    el.querySelectorAll("[data-evidence-verify]").forEach((btn) => {
      btn.addEventListener("click", () =>
        runEvidenceAction(btn.dataset.evidenceVerify, "verify", findingId),
      );
    });
    el.querySelectorAll("[data-evidence-analyse]").forEach((btn) => {
      btn.addEventListener("click", () =>
        runEvidenceAction(btn.dataset.evidenceAnalyse, "analyse", findingId),
      );
    });
  } catch (err) {
    el.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

async function runEvidenceAction(eventId, action, findingId) {
  const resultEl = document.getElementById(`evidence-action-result-${eventId}`);
  if (!investigatorState.investigator) {
    resultEl.textContent = "Sign in as an investigator first.";
    resultEl.className = "result-text error";
    return;
  }
  resultEl.textContent = "Working...";
  resultEl.className = "result-text";
  try {
    const result = await apiRequest(
      `/forensics/evidence/${eventId}/${action}`,
      {
        method: "POST",
        headers: investigatorHeaders(),
        body: JSON.stringify({}),
      },
    );
    resultEl.textContent =
      action === "verify"
        ? `Verified: ${result.integrity_status || ""}`
        : "Recorded.";
    resultEl.className = "result-text success";
    loadCustody(findingId);
  } catch (err) {
    resultEl.textContent = err.message;
    resultEl.className = "result-text error";
  }
}

async function loadCustody(findingId) {
  const el = document.getElementById("custody-content");
  el.innerHTML = '<div class="loading-text">Loading custody history...</div>';
  try {
    const custody = await apiRequest(
      `/forensics/investigations/${findingId}/custody`,
    );
    const eventIds = Object.keys(custody);
    if (!eventIds.length) {
      el.innerHTML =
        '<div class="empty-state">No custody records found for this evidence item.</div>';
      return;
    }
    el.innerHTML = eventIds
      .map((eventId) => {
        const records = custody[eventId];
        return `<div class="panel">
        <h4 style="margin-top:0;" class="hash-cell">${shortHash(eventId)}</h4>
        <table><thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>From</th><th>To</th><th>Reason</th><th>Integrity</th></tr></thead>
        <tbody>${records
          .map(
            (r) => `<tr>
          <td>${formatTimestamp(r.timestamp)}</td>
          <td>${escapeHtml(custodyActorLabel(r.actor))}</td>
          <td>${escapeHtml(custodyActionLabel(r.action))}</td>
          <td>${escapeHtml(r.from_holder ? custodyActorLabel(r.from_holder) : "—")}</td>
          <td>${escapeHtml(r.to_holder ? custodyActorLabel(r.to_holder) : "—")}</td>
          <td>${escapeHtml(r.reason || "—")}</td>
          <td>${badge(r.integrity_status || "UNKNOWN", r.integrity_status === "VALID" ? "valid" : "invalid")}</td>
        </tr>`,
          )
          .join("")}</tbody></table>
      </div>`;
      })
      .join("");
  } catch (err) {
    el.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}
async function loadEvaluation() {
  const overallEl = document.getElementById("evaluation-overall");
  const byScenarioEl = document.getElementById("evaluation-by-scenario");
  overallEl.innerHTML =
    '<div class="loading-text">Loading evaluation summary...</div>';
  byScenarioEl.innerHTML = "";
  try {
    const summary = await apiRequest("/forensics/evaluation/summary");
    const overall = summary.overall || {};
    if (!overall.findings_evaluated) {
      overallEl.innerHTML =
        '<div class="empty-state">No evaluation results are available. Run a scenario and evaluate the findings.</div>';
      return;
    }
    overallEl.innerHTML = `
      ${metricCard("Findings Evaluated", overall.findings_evaluated)}
      ${metricCard("Avg Detection Latency", overall.average_detection_latency_ms != null ? overall.average_detection_latency_ms + " ms" : "—")}
      ${metricCard("Avg Log Completeness", overall.average_log_completeness_percent != null ? overall.average_log_completeness_percent + "%" : "—")}
      ${metricCard("Avg Evidence Preservation", overall.average_evidence_preservation_rate_percent != null ? overall.average_evidence_preservation_rate_percent + "%" : "—")}
    `;
    const byScenario = summary.by_scenario || {};
    const scenarioTypes = Object.keys(byScenario);
    if (!scenarioTypes.length) {
      byScenarioEl.innerHTML =
        '<div class="empty-state">No scenario-level results yet.</div>';
      return;
    }
    byScenarioEl.innerHTML = `<table>
      <thead><tr><th>Scenario</th><th>Findings</th><th>Avg Latency (ms)</th><th>Avg Completeness</th><th>Avg Preservation</th></tr></thead>
      <tbody>${scenarioTypes
        .map((type) => {
          const d = byScenario[type];
          return `<tr><td>${humanizeEventType(type)}</td><td>${d.findings_evaluated}</td>
          <td>${d.average_detection_latency_ms != null ? d.average_detection_latency_ms : "—"}</td>
          <td>${d.average_log_completeness_percent != null ? d.average_log_completeness_percent + "%" : "—"}</td>
          <td>${d.average_evidence_preservation_rate_percent != null ? d.average_evidence_preservation_rate_percent + "%" : "—"}</td></tr>`;
        })
        .join("")}</tbody></table>`;
  } catch (err) {
    overallEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

function initEvaluateButton() {
  document
    .getElementById("evaluate-all-btn")
    .addEventListener("click", async () => {
      const feedback = document.getElementById("evaluate-feedback");
      feedback.innerHTML =
        '<div class="loading-text">Evaluating findings...</div>';
      try {
        await apiRequest("/forensics/evaluate", { method: "POST" });
        feedback.innerHTML =
          '<div class="result-text success">Evaluation complete.</div>';
        loadEvaluation();
        loadDashboard();
      } catch (err) {
        feedback.innerHTML = `<div class="result-text error">${escapeHtml(err.message)}</div>`;
      }
    });
}