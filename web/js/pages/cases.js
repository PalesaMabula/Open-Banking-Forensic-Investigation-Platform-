// ================================================
// Cases page and account-based investigation
// ================================================
function refreshCasesUI() {
  const createPanel = document.getElementById("cases-create-panel");
  const signInNotice = document.getElementById("cases-signin-notice");
  if (investigatorState.investigator) {
    createPanel.classList.remove("hidden");
    signInNotice.classList.add("hidden");
  } else {
    createPanel.classList.add("hidden");
    signInNotice.classList.remove("hidden");
  }
  loadCasesList();
}

function initCasesPage() {
  document
    .getElementById("case-create-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const resultEl = document.getElementById("case-create-result");
      const title = document.getElementById("case-title").value.trim();
      const accountId =
        document.getElementById("case-account-id").value.trim() || null;
      const findingId =
        document.getElementById("case-finding-id").value.trim() || null;
      if (!title) return;

      try {
        const created = await apiRequest("/cases", {
          method: "POST",
          headers: investigatorHeaders(),
          body: JSON.stringify({
            title,
            account_id: accountId,
            finding_id: findingId,
          }),
        });
        resultEl.textContent = `Case created: ${created.case_reference}`;
        resultEl.className = "result-text success";
        document.getElementById("case-create-form").reset();
        loadCasesList();
        loadFindings();
      } catch (err) {
        resultEl.textContent = err.message;
        resultEl.className = "result-text error";
      }
    });
}

async function loadCasesList() {
  const wrap = document.getElementById("cases-table-wrap");
  wrap.innerHTML = '<div class="loading-text">Loading cases...</div>';
  try {
    const cases = await apiRequest("/cases");
    if (!cases.length) {
      wrap.innerHTML = '<div class="empty-state">No cases created yet.</div>';
      return;
    }
    wrap.innerHTML = `<table>
      <thead><tr><th>Reference</th><th>Title</th><th>Status</th><th>Assigned</th><th>Created</th><th></th></tr></thead>
      <tbody>${cases
        .map(
          (c) => `<tr>
        <td class="hash-cell">${escapeHtml(c.case_reference)}</td>
        <td>${escapeHtml(c.title)}</td>
        <td>${badge(c.status, c.status)}</td>
        <td>${escapeHtml(c.assigned_investigator_name || "—")}</td>
        <td>${formatTimestamp(c.created_at)}</td>
        <td><button class="btn btn-small" data-open-case="${c.case_id}">View Case</button></td>
      </tr>`,
        )
        .join("")}</tbody>
    </table>`;
    wrap.querySelectorAll("[data-open-case]").forEach((btn) => {
      btn.addEventListener("click", () => openCaseDetail(btn.dataset.openCase));
    });
  } catch (err) {
    wrap.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

async function openCaseDetail(caseId) {
  const panel = document.getElementById("case-detail-panel");
  panel.classList.remove("hidden");
  panel.innerHTML = '<div class="loading-text">Loading case...</div>';
  try {
    const c = await apiRequest(`/cases/${caseId}`);
    const investigators = await apiRequest("/investigators");
    const maskedAccount = c.account_id ? maskAccount(c.account_id) : "—";

    panel.innerHTML = `
      <h3 style="margin-top:0;">${escapeHtml(c.case_reference)}</h3>
      <div class="kv-grid">
        <div><div class="kv-label">Title</div><div class="kv-value">${escapeHtml(c.title)}</div></div>
        <div><div class="kv-label">Status</div><div class="kv-value">${badge(c.status, c.status)}</div></div>
        <div><div class="kv-label">Assigned</div><div class="kv-value">${escapeHtml(c.assigned_investigator ? c.assigned_investigator.display_name : "—")}</div></div>
        <div><div class="kv-label">Account</div><div class="kv-value hash-cell">${escapeHtml(maskedAccount)}</div></div>
        <div><div class="kv-label">Originating Finding</div><div class="kv-value hash-cell">${escapeHtml(c.finding_id || "—")}</div></div>
        <div><div class="kv-label">Created</div><div class="kv-value">${formatTimestamp(c.created_at)}</div></div>
        <div><div class="kv-label">Updated</div><div class="kv-value">${formatTimestamp(c.updated_at)}</div></div>
      </div>
      ${
        investigatorState.investigator
          ? `
        <div class="form-grid" style="margin-top:16px; max-width:280px;">
          <label>Reassign To
            <select id="case-reassign-select">
              ${(() => {
                const assignedId = c.assigned_investigator
                  ? c.assigned_investigator.investigator_id
                  : null;
                let list = investigators.filter((i) => i.status === "ACTIVE");
                if (
                  assignedId &&
                  !list.find((i) => i.investigator_id === assignedId)
                ) {
                  const assignedButInactive = investigators.find(
                    (i) => i.investigator_id === assignedId,
                  );
                  if (assignedButInactive)
                    list = [assignedButInactive, ...list];
                }
                return list
                  .map(
                    (i) =>
                      `<option value="${i.investigator_id}" ${assignedId === i.investigator_id ? "selected" : ""}>${escapeHtml(i.display_name)} — ${escapeHtml(i.role)}${i.status === "INACTIVE" ? " (Inactive)" : ""}</option>`,
                  )
                  .join("");
              })()}
            </select>
          </label>
          <button id="case-reassign-btn" class="btn btn-small">Reassign</button>
          <label>Status
            <select id="case-status-select">
              <option value="OPEN" ${c.status === "OPEN" ? "selected" : ""}>Open</option>
              <option value="IN_PROGRESS" ${c.status === "IN_PROGRESS" ? "selected" : ""}>In Progress</option>
              <option value="CLOSED" ${c.status === "CLOSED" ? "selected" : ""}>Closed</option>
            </select>
          </label>
          <button id="case-status-btn" class="btn btn-small">Update Status</button>
          <div id="case-action-result" class="result-text"></div>
        </div>
      `
          : ""
      }
      <div class="app-actions" style="margin-top:16px;">
        ${c.finding_id ? `<button class="btn btn-primary" id="case-view-finding-btn">View Finding</button>` : ""}
        <button class="btn btn-primary" id="case-start-account-investigation-btn" ${c.account_id ? "" : "disabled"}>Start Account Investigation</button>
      </div>
      ${!c.account_id ? `<p style="font-size:13px; color:var(--muted); margin-top:8px;">No account is associated with this case.</p>` : ""}

      <div id="account-investigation-panel" class="hidden" style="margin-top:20px;"></div>
    `;

    if (c.finding_id) {
      document
        .getElementById("case-view-finding-btn")
        .addEventListener("click", () => goToInvestigation(c.finding_id));
    }
    if (c.account_id) {
      document
        .getElementById("case-start-account-investigation-btn")
        .addEventListener("click", () => {
          toggleAccountInvestigation(c.account_id);
        });
    }
    if (investigatorState.investigator) {
      document
        .getElementById("case-reassign-btn")
        .addEventListener("click", async () => {
          const newId = document.getElementById("case-reassign-select").value;
          const resEl = document.getElementById("case-action-result");
          try {
            await apiRequest(`/cases/${caseId}/assign`, {
              method: "PATCH",
              headers: investigatorHeaders(),
              body: JSON.stringify({ investigator_id: newId }),
            });
            resEl.textContent = "Case reassigned.";
            resEl.className = "result-text success";
            openCaseDetail(caseId);
            loadCasesList();
          } catch (err) {
            resEl.textContent = err.message;
            resEl.className = "result-text error";
          }
        });
      document
        .getElementById("case-status-btn")
        .addEventListener("click", async () => {
          const newStatus = document.getElementById("case-status-select").value;
          const resEl = document.getElementById("case-action-result");
          try {
            await apiRequest(`/cases/${caseId}/status`, {
              method: "PATCH",
              headers: investigatorHeaders(),
              body: JSON.stringify({ status: newStatus }),
            });
            resEl.textContent = "Status updated.";
            resEl.className = "result-text success";
            openCaseDetail(caseId);
            loadCasesList();
          } catch (err) {
            resEl.textContent = err.message;
            resEl.className = "result-text error";
          }
        });
    }
  } catch (err) {
    panel.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

async function toggleAccountInvestigation(accountId) {
  const panel = document.getElementById("account-investigation-panel");
  if (!panel.classList.contains("hidden")) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }

  panel.classList.remove("hidden");
  panel.innerHTML =
    '<div class="loading-text">Loading account investigation...</div>';

  try {
    const data = await apiRequest(
      `/forensics/account/${accountId}/investigation`,
      {
        headers: investigatorHeaders(),
      },
    );
    renderAccountInvestigation(panel, data);
  } catch (err) {
    panel.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

function renderAccountInvestigation(panel, data) {
  const ov = data.overview || {};
  const evidenceOk = data.evidence_integrity === "VALID";
  const custodyOk = data.custody_integrity === "VALID";

  panel.innerHTML = `
    <div class="panel">
      <h3 style="margin-top:0;">Account Investigation — <span class="hash-cell">${escapeHtml(maskAccount(data.account_id))}</span></h3>
      <div class="tabs">
        <button class="tab-btn acct-tab-btn active" data-acct-tab="overview">Overview</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="timeline">Timeline</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="consents">Consents</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="applications">Applications</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="api-comm">API Communication</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="findings">Findings</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="evidence">Evidence</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="custody">Chain of Custody</button>
        <button class="tab-btn acct-tab-btn" data-acct-tab="integrity">Integrity</button>
      </div>

      <div class="tab-panel acct-tab-panel active" data-acct-panel="overview">
        <div class="metric-grid">
          ${metricCard("Connected Applications", ov.connected_application_count ?? "—")}
          ${metricCard("Active Consents", ov.active_consent_count ?? "—")}
          ${metricCard("Findings", ov.total_findings ?? "—")}
          ${metricCard("API Interactions", ov.total_api_interactions ?? "—")}
          ${metricCard("Evidence Items", ov.total_evidence_items ?? "—")}
        </div>
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="timeline">
        ${
          data.timeline && data.timeline.length
            ? `<ul class="timeline">${data.timeline
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
                .join("")}</ul>`
            : '<div class="empty-state">No timeline activity for this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="consents">
        ${
          data.consents && data.consents.length
            ? `<table>
          <thead><tr><th>Application</th><th>Permissions</th><th>Status</th><th>Created</th></tr></thead>
          <tbody>${data.consents
            .map(
              (c) => `<tr>
            <td>${escapeHtml(c.application_name)}</td>
            <td>${c.permissions.map(permLabel).join(", ")}</td>
            <td>${badge(c.status, c.status)}</td>
            <td>${formatTimestamp(c.created_at)}</td>
          </tr>`,
            )
            .join("")}</tbody>
        </table>`
            : '<div class="empty-state">No consents recorded for this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="applications">
        ${
          data.applications && data.applications.length
            ? `<table>
          <thead><tr><th>Application</th><th>Status</th></tr></thead>
          <tbody>${data.applications
            .map(
              (a) => `<tr>
            <td>${escapeHtml(a.application_name)}</td>
            <td>${badge(a.status, a.status === "ACTIVE" ? "AUTHORIZED" : "NONE")}</td>
          </tr>`,
            )
            .join("")}</tbody>
        </table>`
            : '<div class="empty-state">No applications associated with this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="api-comm">
        ${
          data.api_communication && data.api_communication.length
            ? `<table>
          <thead><tr><th>Time</th><th>Method</th><th>Endpoint</th><th>Status</th></tr></thead>
          <tbody>${data.api_communication
            .map(
              (i) => `<tr>
            <td>${formatTimestamp(i.timestamp)}</td>
            <td>${escapeHtml(i.http_method)}</td>
            <td>${escapeHtml(i.endpoint)}</td>
            <td>${escapeHtml(i.response_status)}</td>
          </tr>`,
            )
            .join("")}</tbody>
        </table>`
            : '<div class="empty-state">No API communication captured for this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="findings">
        ${
          data.findings && data.findings.length
            ? `<table>
          <thead><tr><th>Scenario</th><th>Severity</th><th>Status</th><th>Detected At</th><th></th></tr></thead>
          <tbody>${data.findings
            .map(
              (f) => `<tr>
            <td>${humanizeEventType(f.scenario_type)}</td>
            <td>${badge(f.severity, f.severity)}</td>
            <td>${badge(f.status, f.status)}</td>
            <td>${formatTimestamp(f.detected_at)}</td>
            <td><button class="btn btn-small" data-acct-view-finding="${f.finding_id}">View</button></td>
          </tr>`,
            )
            .join("")}</tbody>
        </table>`
            : '<div class="empty-state">No findings associated with this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="evidence">
        ${
          data.evidence && data.evidence.length
            ? data.evidence
                .map((item) => {
                  const ok = item.integrity_status === "VALID";
                  return `<div class="panel">
            <div class="kv-grid">
              <div><div class="kv-label">Event Type</div><div class="kv-value">${humanizeEventType(item.event_type)}</div></div>
              <div><div class="kv-label">Timestamp</div><div class="kv-value">${formatTimestamp(item.timestamp)}</div></div>
              <div><div class="kv-label">Integrity</div><div class="kv-value">${badge(item.integrity_status, ok ? "valid" : "invalid")}</div></div>
              <div><div class="kv-label">Custody Records</div><div class="kv-value">${item.custody_event_count}</div></div>
            </div>
            <div style="margin-top:8px;"><div class="kv-label">Event Hash</div><div class="hash-cell">${shortHash(item.event_hash)}</div></div>
          </div>`;
                })
                .join("")
            : '<div class="empty-state">No evidence captured for this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="custody">
        ${
          data.evidence && data.evidence.length
            ? data.evidence
                .map((item) => {
                  const records =
                    (data.custody && data.custody[item.event_id]) || [];
                  if (!records.length) return "";
                  return `<div class="panel">
            <h4 style="margin-top:0;" class="hash-cell">${shortHash(item.event_id)}</h4>
            <table><thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Reason</th><th>Integrity</th></tr></thead>
            <tbody>${records
              .map(
                (r) => `<tr>
              <td>${formatTimestamp(r.timestamp)}</td>
              <td>${escapeHtml(custodyActorLabel(r.actor))}</td>
              <td>${escapeHtml(custodyActionLabel(r.action))}</td>
              <td>${escapeHtml(r.reason || "—")}</td>
              <td>${badge(r.integrity_status || "UNKNOWN", r.integrity_status === "VALID" ? "valid" : "invalid")}</td>
            </tr>`,
              )
              .join("")}</tbody></table>
          </div>`;
                })
                .join("")
            : '<div class="empty-state">No custody records for this account.</div>'
        }
      </div>

      <div class="tab-panel acct-tab-panel" data-acct-panel="integrity">
        <div class="metric-grid">
          ${metricCard("Evidence Integrity", data.evidence_integrity, evidenceOk ? "status-valid" : "status-invalid")}
          ${metricCard("Custody Integrity", data.custody_integrity, custodyOk ? "status-valid" : "status-invalid")}
        </div>
      </div>
    </div>
  `;

  panel.querySelectorAll(".acct-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      panel
        .querySelectorAll(".acct-tab-btn")
        .forEach((b) => b.classList.remove("active"));
      panel
        .querySelectorAll(".acct-tab-panel")
        .forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      panel
        .querySelector(
          `.acct-tab-panel[data-acct-panel="${btn.dataset.acctTab}"]`,
        )
        .classList.add("active");
    });
  });

  panel.querySelectorAll("[data-acct-view-finding]").forEach((btn) => {
    btn.addEventListener("click", () =>
      goToInvestigation(btn.dataset.acctViewFinding),
    );
  });
}