// ================================================
// Dashboard page
// ================================================
async function loadDashboard() {
  const metricsEl = document.getElementById("dashboard-metrics");
  const appsEl = document.getElementById("dashboard-apps");
  const recentEl = document.getElementById("dashboard-recent-findings");
  metricsEl.innerHTML = '<div class="loading-text">Loading dashboard...</div>';

  try {
    const summary = await apiRequest("/forensics/dashboard/summary");
    const evidenceValid =
      summary.evidence_integrity && summary.evidence_integrity.valid;
    const custodyValid =
      summary.custody_integrity && summary.custody_integrity.valid;

    toggleWarning(
      "integrity-warning",
      !evidenceValid,
      "Evidence integrity verification failed. Investigation results should be reviewed carefully.",
    );
    toggleWarning(
      "custody-warning",
      !custodyValid,
      "Custody chain verification failed. Custody history should be reviewed carefully.",
    );

    const ev = summary.evaluation_overall || {};

    metricsEl.innerHTML = `
      ${metricCard("Open Findings", summary.open_findings ?? "—")}
      ${metricCard("Critical Findings", summary.critical_findings ?? "—")}
      ${metricCard("Evidence Integrity", evidenceValid ? "VALID" : "INVALID", evidenceValid ? "status-valid" : "status-invalid")}
      ${metricCard("Custody Integrity", custodyValid ? "VALID" : "INVALID", custodyValid ? "status-valid" : "status-invalid")}
      ${metricCard("Avg Detection Latency", ev.average_detection_latency_ms != null ? ev.average_detection_latency_ms + " ms" : "—")}
      ${metricCard("Log Completeness", ev.average_log_completeness_percent != null ? ev.average_log_completeness_percent + "%" : "—")}
      ${metricCard("Evidence Preservation", ev.average_evidence_preservation_rate_percent != null ? ev.average_evidence_preservation_rate_percent + "%" : "—")}
    `;
  } catch (err) {
    metricsEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }

  try {
    const ob = await apiRequest("/open-banking/summary");
    appsEl.innerHTML =
      ob.applications
        .map((a) =>
          metricCard(
            a.application_name,
            a.consent_status === "AUTHORIZED" ? "Active" : "No Consent",
            a.consent_status === "AUTHORIZED"
              ? "status-valid"
              : "status-invalid",
          ),
        )
        .join("") ||
      '<div class="empty-state">No connected applications yet.</div>';
  } catch (err) {
    appsEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }

  try {
    const findings = await apiRequest("/forensics/findings");
    const recent = findings.slice(0, 5);
    if (!recent.length) {
      recentEl.innerHTML =
        '<div class="empty-state">No findings have been detected yet.</div>';
    } else {
      recentEl.innerHTML = `<table>
        <thead><tr><th>Scenario</th><th>Severity</th><th>Status</th><th>Detected</th></tr></thead>
        <tbody>${recent
          .map(
            (f) => `<tr>
          <td>${humanizeEventType(f.scenario_type)}</td>
          <td>${badge(f.severity, f.severity)}</td>
          <td>${badge(f.status, f.status)}</td>
          <td>${formatTimestamp(f.detected_at)}</td>
        </tr>`,
          )
          .join("")}</tbody>
      </table>`;
    }
  } catch (err) {
    recentEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}