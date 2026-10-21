// ================================================
// Customer / BudgetWise / InsureWise pages
// ================================================
function initCustomerPage() {
  document
    .getElementById("customer-load-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const accountId = document
        .getElementById("customer-account-id")
        .value.trim();
      if (!accountId) return;
      state.lastCustomerAccountId = accountId;
      setActiveAccount(accountId);
      document
        .getElementById("customer-refresh-btn")
        .classList.remove("hidden");
      await loadCustomerContent(accountId);
    });

  document
    .getElementById("customer-refresh-btn")
    .addEventListener("click", () => {
      if (state.lastCustomerAccountId)
        loadCustomerContent(state.lastCustomerAccountId);
    });
}

async function loadCustomerContent(accountId) {
  const el = document.getElementById("customer-content");
  el.innerHTML = '<div class="loading-text">Loading account...</div>';

  let accountView;
  try {
    accountView = await apiRequest(
      `/open-banking/customer/account/${accountId}`,
    );
  } catch (err) {
    el.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  let accessData = { requests: [] };
  try {
    accessData = await apiRequest(
      `/open-banking/customer/account/${accountId}/access`,
    );
  } catch (err) {
    /* leave empty */
  }

  const requests = accessData.requests || [];
  const pending = requests.filter((r) => r.status === "PENDING");
  const authorized = requests.filter((r) => r.status === "AUTHORIZED");

  let html = "";

  if (!accountView.success) {
    html += `<div class="warning-banner">${escapeHtml(accountView.detail || "Account not found.")}</div>`;
  } else {
    const acc = accountView.account || {};
    html += `<div class="panel">
      <h3 style="margin-top:0;">Account Details</h3>
      <div class="kv-grid">
        <div><div class="kv-label">Account Name</div><div class="kv-value">${escapeHtml(acc.accountName || "—")}</div></div>
        <div><div class="kv-label">Account Number</div><div class="kv-value hash-cell">${escapeHtml(acc.accountId || accountId)}</div></div>
        <div><div class="kv-label">Product</div><div class="kv-value">${escapeHtml(acc.productName || acc.accountType || "—")}</div></div>
        <div><div class="kv-label">Currency</div><div class="kv-value">${escapeHtml(acc.currencyCode || "—")}</div></div>
      </div>
    </div>`;

    const transactions = accountView.transactions || [];
    html += `<div class="panel">
      <h3 style="margin-top:0;">Transactions</h3>
      ${
        transactions.length
          ? `<table>
        <thead><tr><th>Date</th><th>Description</th><th>Type</th><th>Amount</th></tr></thead>
        <tbody>${transactions
          .slice(0, 25)
          .map(
            (t) => `<tr>
          <td>${escapeHtml(t.transactionDate || t.postingDate || "—")}</td>
          <td>${escapeHtml(t.description || "—")}</td>
          <td>${escapeHtml(t.type || "—")}</td>
          <td>${escapeHtml(t.amount != null ? t.amount : "—")}</td>
        </tr>`,
          )
          .join("")}</tbody>
      </table>`
          : '<div class="empty-state">No transactions available.</div>'
      }
    </div>`;
  }

  html += `<div class="panel">
    <h3 style="margin-top:0;">Access Requests</h3>
    ${
      pending.length
        ? pending
            .map(
              (r) => `
      <div class="kv-grid" style="margin-bottom:12px; padding-bottom:12px; border-bottom:1px solid var(--border);">
        <div><div class="kv-label">Application</div><div class="kv-value">${escapeHtml(r.application_name)}</div></div>
        <div><div class="kv-label">Requested Access</div><div class="kv-value">${r.permissions.map(permLabel).join(", ")}</div></div>
        <div><div class="kv-label">Requested</div><div class="kv-value">${formatTimestamp(r.created_at)}</div></div>
        <div><div class="kv-label">Status</div><div class="kv-value">${badge("Awaiting Approval", "PENDING")}</div></div>
        <div style="display:flex; gap:8px; align-items:flex-end;">
          <button class="btn btn-small btn-primary" data-approve="${r.consent_id}">Approve</button>
          <button class="btn btn-small" data-reject="${r.consent_id}">Reject</button>
        </div>
      </div>`,
            )
            .join("")
        : '<div class="empty-state">No access requests for this account.</div>'
    }
  </div>`;

  html += `<div class="panel">
    <h3 style="margin-top:0;">Applications With Access</h3>
    ${
      authorized.length
        ? authorized
            .map(
              (r) => `
      <div class="kv-grid" style="margin-bottom:12px; padding-bottom:12px; border-bottom:1px solid var(--border);">
        <div><div class="kv-label">Application</div><div class="kv-value">${escapeHtml(r.application_name)}</div></div>
        <div><div class="kv-label">Account Information</div><div class="kv-value">${r.permissions.includes("accounts") ? "Allowed" : "Not Allowed"}</div></div>
        <div><div class="kv-label">Transaction History</div><div class="kv-value">${r.permissions.includes("transactions") ? "Allowed" : "Not Allowed"}</div></div>
        <div><div class="kv-label">Status</div><div class="kv-value">${badge("Active", "AUTHORIZED")}</div></div>
      </div>`,
            )
            .join("")
        : '<div class="empty-state">No applications currently have access.</div>'
    }
  </div>`;

  el.innerHTML = html;

  el.querySelectorAll("[data-approve]").forEach((btn) => {
    btn.addEventListener("click", () =>
      handleConsentDecision(btn.dataset.approve, "approve", accountId),
    );
  });
  el.querySelectorAll("[data-reject]").forEach((btn) => {
    btn.addEventListener("click", () =>
      handleConsentDecision(btn.dataset.reject, "reject", accountId),
    );
  });
}

async function handleConsentDecision(consentId, decision, accountId) {
  const el = document.getElementById("customer-content");
  try {
    const path =
      decision === "approve"
        ? `/consents/${consentId}/authorize`
        : `/consents/${consentId}/reject`;
    await apiRequest(path, { method: "POST" });
    loadCustomerContent(accountId);
    loadDashboard();
  } catch (err) {
    el.insertAdjacentHTML(
      "afterbegin",
      `<div class="warning-banner">${escapeHtml(err.message)}</div>`,
    );
  }
}
function initAppPage(appName, prefix, permissions) {
  document
    .getElementById(`${prefix}-request-form`)
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const accountId = document
        .getElementById(`${prefix}-account-id`)
        .value.trim();
      if (!accountId) return;

      const statusEl = document.getElementById(`${prefix}-status`);
      statusEl.innerHTML =
        '<div class="loading-text">Sending access request...</div>';

      try {
        await apiRequest(`/open-banking/${appName}/request-access`, {
          method: "POST",
          body: JSON.stringify({ account_id: accountId, permissions }),
        });
        state.lastAppAccountId[appName] = accountId;
        setActiveAccount(accountId);
        document
          .getElementById(`${prefix}-refresh-btn`)
          .classList.remove("hidden");
        loadAppStatus(appName, prefix, accountId);
        loadDashboard();
      } catch (err) {
        statusEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
      }
    });

  document
    .getElementById(`${prefix}-refresh-btn`)
    .addEventListener("click", () => {
      const accountId = state.lastAppAccountId[appName];
      if (accountId) loadAppStatus(appName, prefix, accountId);
    });
}

async function loadAppStatus(appName, prefix, accountId) {
  const statusEl = document.getElementById(`${prefix}-status`);
  statusEl.innerHTML = '<div class="loading-text">Loading status...</div>';

  let accessData;
  try {
    accessData = await apiRequest(
      `/open-banking/customer/account/${accountId}/access`,
    );
  } catch (err) {
    statusEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
    return;
  }

  const requests = (accessData.requests || []).filter(
    (r) => r.application_name === appName,
  );
  if (!requests.length) {
    statusEl.innerHTML =
      '<div class="empty-state">No access request sent yet.</div>';
    return;
  }

  const latest = requests[0];
  const statusLabel =
    latest.status === "PENDING"
      ? "Awaiting Approval"
      : latest.status === "AUTHORIZED"
        ? "Approved"
        : latest.status === "REJECTED"
          ? "Rejected"
          : latest.status;

  let html = `<div class="panel">
    <h3 style="margin-top:0;">Access Request</h3>
    <div class="kv-grid">
      <div><div class="kv-label">Account</div><div class="kv-value hash-cell">${escapeHtml(maskAccount(accountId))}</div></div>
      <div><div class="kv-label">Requested Access</div><div class="kv-value">${latest.permissions.map(permLabel).join(", ")}</div></div>
      <div><div class="kv-label">Status</div><div class="kv-value">${badge(statusLabel, latest.status)}</div></div>
    </div>
  </div>`;

  if (latest.status === "AUTHORIZED") {
    html += `<div class="panel">
      <h3 style="margin-top:0;">Connected Customer</h3>
      <div class="kv-grid">
        <div><div class="kv-label">Customer</div><div class="kv-value">Customer 001</div></div>
        <div><div class="kv-label">Account</div><div class="kv-value hash-cell">${escapeHtml(maskAccount(accountId))}</div></div>
        <div><div class="kv-label">Consent</div><div class="kv-value">${badge("Approved", "AUTHORIZED")}</div></div>
      </div>
      <div class="kv-label" style="margin-top:12px;">Authorized Access</div>
      <ul class="perm-list">
        <li class="${latest.permissions.includes("accounts") ? "perm-allowed" : "perm-denied"}">Account Information</li>
        <li class="${latest.permissions.includes("transactions") ? "perm-allowed" : "perm-denied"}">Transaction History</li>
      </ul>
      <div class="app-actions" style="margin-top:10px;">
        <button class="btn btn-small" data-view-account="${escapeHtml(appName)}|${escapeHtml(accountId)}|${prefix}">View Account</button>
        <button class="btn btn-small" data-view-transactions="${escapeHtml(appName)}|${escapeHtml(accountId)}|${prefix}">View Transactions</button>
      </div>
      <div id="${prefix}-result" class="result-text"></div>
    </div>`;
  } else if (latest.status === "REJECTED") {
    html += `<div class="empty-state">Access request rejected.</div>`;
  } else {
    html += `<div class="empty-state">Awaiting customer approval.</div>`;
  }

  statusEl.innerHTML = html;

  statusEl.querySelectorAll("[data-view-account]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const [appN, accId, pfx] = btn.dataset.viewAccount.split("|");
      viewAppAccount(appN, accId, pfx);
    });
  });
  statusEl.querySelectorAll("[data-view-transactions]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const [appN, accId, pfx] = btn.dataset.viewTransactions.split("|");
      viewAppTransactions(appN, accId, pfx);
    });
  });
}

async function viewAppAccount(appName, accountId, prefix) {
  const resultEl = document.getElementById(`${prefix}-result`);
  resultEl.innerHTML = '<div class="loading-text">Loading account...</div>';
  resultEl.className = "result-text";
  try {
    const result = await apiRequest(`/open-banking/${appName}/view-account`, {
      method: "POST",
      body: JSON.stringify({ account_id: accountId }),
    });
    if (!result.success) {
      resultEl.innerHTML = `<div class="warning-banner">Access Denied — ${escapeHtml(result.detail || "")}</div>`;
    } else {
      setActiveAccount(accountId);
      const accounts =
        (result.data &&
          (result.data.accounts ||
            (result.data.data && result.data.data.accounts))) ||
        [];
      const match =
        accounts.find((a) => a.accountId === accountId) || accounts[0];

      if (!match) {
        resultEl.innerHTML =
          '<div class="empty-state">No account data returned.</div>';
      } else {
        resultEl.innerHTML = `<div class="panel" style="margin-top:10px;">
          <h4 style="margin-top:0;">Account Details</h4>
          <div class="kv-grid">
            <div><div class="kv-label">Account Name</div><div class="kv-value">${escapeHtml(match.accountName || "—")}</div></div>
            <div><div class="kv-label">Account Number</div><div class="kv-value hash-cell">${escapeHtml(match.accountId || accountId)}</div></div>
            <div><div class="kv-label">Product</div><div class="kv-value">${escapeHtml(match.productName || match.accountType || "—")}</div></div>
            <div><div class="kv-label">Currency</div><div class="kv-value">${escapeHtml(match.currencyCode || "—")}</div></div>
          </div>
        </div>`;
      }
    }
  } catch (err) {
    resultEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
  loadApiCommunication();
}

async function viewAppTransactions(appName, accountId, prefix) {
  const resultEl = document.getElementById(`${prefix}-result`);
  resultEl.innerHTML =
    '<div class="loading-text">Loading transactions...</div>';
  resultEl.className = "result-text";
  try {
    const result = await apiRequest(
      `/open-banking/${appName}/view-transactions`,
      {
        method: "POST",
        body: JSON.stringify({ account_id: accountId }),
      },
    );
    if (!result.success) {
      resultEl.innerHTML = `<div class="warning-banner">Access Denied — ${escapeHtml(appName)} is not authorized to access Transaction History for this account.</div>`;
    } else {
      setActiveAccount(accountId);
      const transactions =
        (result.data &&
          (result.data.transactions ||
            (result.data.data && result.data.data.transactions))) ||
        [];
      resultEl.innerHTML = `<div class="panel" style="margin-top:10px;">
        <h4 style="margin-top:0;">Transactions</h4>
        ${
          transactions.length
            ? `<table>
          <thead><tr><th>Date</th><th>Description</th><th>Type</th><th>Amount</th></tr></thead>
          <tbody>${transactions
            .slice(0, 25)
            .map(
              (t) => `<tr>
            <td>${escapeHtml(t.transactionDate || t.postingDate || "—")}</td>
            <td>${escapeHtml(t.description || "—")}</td>
            <td>${escapeHtml(t.type || "—")}</td>
            <td>${escapeHtml(t.amount != null ? t.amount : "—")}</td>
          </tr>`,
            )
            .join("")}</tbody>
        </table>`
            : '<div class="empty-state">No transactions available.</div>'
        }
      </div>`;
    }
  } catch (err) {
    resultEl.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
  loadApiCommunication();
}