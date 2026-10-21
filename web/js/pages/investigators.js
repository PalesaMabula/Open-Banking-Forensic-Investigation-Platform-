// ================================================
// Investigator authentication and Manage Investigators page
// ================================================
function initInvestigatorAuth() {
  document
    .getElementById("home-openbanking-btn")
    .addEventListener("click", enterOpenBankingWorkspace);
  document
    .getElementById("home-investigator-btn")
    .addEventListener("click", () => {
      document.getElementById("investigator-login-error").textContent = "";
      document
        .getElementById("investigator-login-modal")
        .classList.remove("hidden");
    });

  document
    .getElementById("investigator-login-btn")
    .addEventListener("click", () => {
      document.getElementById("investigator-login-error").textContent = "";
      document
        .getElementById("investigator-login-modal")
        .classList.remove("hidden");
    });
  document
    .getElementById("investigator-login-cancel")
    .addEventListener("click", () => {
      document
        .getElementById("investigator-login-modal")
        .classList.add("hidden");
    });
  document
    .getElementById("investigator-login-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("investigator-username").value;
      const password = document.getElementById("investigator-password").value;
      const errorEl = document.getElementById("investigator-login-error");
      try {
        const result = await apiRequest("/investigators/login", {
          method: "POST",
          body: JSON.stringify({ username, password }),
        });
        investigatorState.session = result.session_token;
        investigatorState.investigator = result;
        document
          .getElementById("investigator-login-modal")
          .classList.add("hidden");
        document.getElementById("investigator-login-form").reset();
        renderInvestigatorBar();
        refreshCasesUI();
        enterForensicWorkspace();

        if (state.pendingInvestigationFindingId) {
          const findingId = state.pendingInvestigationFindingId;
          state.pendingInvestigationFindingId = null;
          goToInvestigation(findingId);
        }
      } catch (err) {
        errorEl.textContent = err.message;
      }
    });
  document
    .getElementById("investigator-logout-btn")
    .addEventListener("click", async () => {
      try {
        await apiRequest("/investigators/logout", {
          method: "POST",
          headers: investigatorHeaders(),
        });
      } catch (e) {
        /* ignore */
      }
      investigatorState.session = null;
      investigatorState.investigator = null;
      renderInvestigatorBar();
      refreshCasesUI();
      showHomeScreen();
    });
}

function renderInvestigatorBar() {
  const signedOut = document.getElementById("investigator-signed-out");
  const signedIn = document.getElementById("investigator-signed-in");
  if (investigatorState.investigator) {
    signedOut.classList.add("hidden");
    signedIn.classList.remove("hidden");
    document.getElementById("investigator-name-display").textContent =
      investigatorState.investigator.display_name;
    document.getElementById("investigator-role-display").textContent =
      investigatorState.investigator.role;
  } else {
    signedOut.classList.remove("hidden");
    signedIn.classList.add("hidden");
  }
  refreshInvestigatorsUI();
}

function refreshInvestigatorsUI() {
  const createPanel = document.getElementById("investigators-create-panel");
  const signInNotice = document.getElementById("investigators-signin-notice");
  const isLead =
    investigatorState.investigator &&
    investigatorState.investigator.role === "Lead Investigator";

  if (isLead) {
    createPanel.classList.remove("hidden");
    signInNotice.classList.add("hidden");
  } else {
    createPanel.classList.add("hidden");
    signInNotice.classList.remove("hidden");
  }
  loadInvestigatorsList();
}
let cachedInvestigators = [];

function initInvestigatorsPage() {
  document
    .getElementById("investigator-create-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const resultEl = document.getElementById("investigator-create-result");
      const displayName = document
        .getElementById("new-investigator-display-name")
        .value.trim();
      const username = document
        .getElementById("new-investigator-username")
        .value.trim();
      const password = document.getElementById(
        "new-investigator-password",
      ).value;
      const role = document.getElementById("new-investigator-role").value;
      const status = document.getElementById("new-investigator-status").value;

      if (!displayName || !username || !password) return;

      try {
        const created = await apiRequest("/investigators", {
          method: "POST",
          headers: investigatorHeaders(),
          body: JSON.stringify({
            display_name: displayName,
            username,
            password,
            role,
            status,
          }),
        });
        resultEl.textContent = `Investigator created: ${created.investigator_id}`;
        resultEl.className = "result-text success";
        document.getElementById("investigator-create-form").reset();
        loadInvestigatorsList();
      } catch (err) {
        resultEl.textContent = err.message;
        resultEl.className = "result-text error";
      }
    });
}

async function loadInvestigatorsList() {
  const wrap = document.getElementById("investigators-table-wrap");
  wrap.innerHTML = '<div class="loading-text">Loading investigators...</div>';
  try {
    cachedInvestigators = await apiRequest("/investigators");
    renderInvestigatorsTable();
  } catch (err) {
    wrap.innerHTML = `<div class="warning-banner">${escapeHtml(err.message)}</div>`;
  }
}

function renderInvestigatorsTable() {
  const wrap = document.getElementById("investigators-table-wrap");
  const isLead =
    investigatorState.investigator &&
    investigatorState.investigator.role === "Lead Investigator";

  if (!cachedInvestigators.length) {
    wrap.innerHTML =
      '<div class="empty-state">No investigators registered yet.</div>';
    return;
  }

  const statusLabel = { ACTIVE: "Active", INACTIVE: "Inactive" };

  wrap.innerHTML = `<table>
    <thead><tr><th>Investigator ID</th><th>Display Name</th><th>Username</th><th>Role</th><th>Status</th>${isLead ? "<th></th>" : ""}</tr></thead>
    <tbody>${cachedInvestigators
      .map(
        (inv) => `<tr>
      <td class="hash-cell">${escapeHtml(inv.investigator_id)}</td>
      <td>${escapeHtml(inv.display_name)}</td>
      <td>${escapeHtml(inv.username)}</td>
      <td>${escapeHtml(inv.role)}</td>
      <td>${badge(statusLabel[inv.status] || inv.status, inv.status === "ACTIVE" ? "AUTHORIZED" : "NONE")}</td>
      ${isLead ? `<td><button class="btn btn-small" data-edit-investigator="${inv.investigator_id}">Edit</button></td>` : ""}
    </tr>`,
      )
      .join("")}</tbody>
  </table>`;

  if (isLead) {
    wrap.querySelectorAll("[data-edit-investigator]").forEach((btn) => {
      btn.addEventListener("click", () =>
        openInvestigatorEdit(btn.dataset.editInvestigator),
      );
    });
  }
}

function openInvestigatorEdit(investigatorId) {
  const inv = cachedInvestigators.find(
    (i) => i.investigator_id === investigatorId,
  );
  if (!inv) return;

  const panel = document.getElementById("investigator-edit-panel");
  panel.classList.remove("hidden");
  panel.innerHTML = `
    <h3 style="margin-top:0;">Edit Investigator — ${escapeHtml(inv.investigator_id)}</h3>
    <form id="investigator-edit-form" class="form-grid" style="max-width:360px;">
      <label>Display Name
        <input type="text" id="edit-investigator-display-name" value="${escapeHtml(inv.display_name)}" required>
      </label>
      <label>Role
        <select id="edit-investigator-role">
          <option value="Lead Investigator" ${inv.role === "Lead Investigator" ? "selected" : ""}>Lead Investigator</option>
          <option value="Forensic Analyst" ${inv.role === "Forensic Analyst" ? "selected" : ""}>Forensic Analyst</option>
        </select>
      </label>
      <label>Status
        <select id="edit-investigator-status">
          <option value="ACTIVE" ${inv.status === "ACTIVE" ? "selected" : ""}>Active</option>
          <option value="INACTIVE" ${inv.status === "INACTIVE" ? "selected" : ""}>Inactive</option>
        </select>
      </label>
      <div class="modal-actions" style="justify-content:flex-start;">
        <button type="submit" class="btn btn-primary">Save Changes</button>
        <button type="button" id="investigator-edit-cancel" class="btn">Cancel</button>
      </div>
    </form>
    <div id="investigator-edit-result" class="result-text"></div>
  `;

  document
    .getElementById("investigator-edit-cancel")
    .addEventListener("click", () => {
      panel.classList.add("hidden");
      panel.innerHTML = "";
    });

  document
    .getElementById("investigator-edit-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const resultEl = document.getElementById("investigator-edit-result");
      const displayName = document
        .getElementById("edit-investigator-display-name")
        .value.trim();
      const role = document.getElementById("edit-investigator-role").value;
      const status = document.getElementById("edit-investigator-status").value;

      try {
        await apiRequest(`/investigators/${investigatorId}`, {
          method: "PATCH",
          headers: investigatorHeaders(),
          body: JSON.stringify({ display_name: displayName, role, status }),
        });
        resultEl.textContent = "Investigator updated.";
        resultEl.className = "result-text success";
        loadInvestigatorsList();
      } catch (err) {
        resultEl.textContent = err.message;
        resultEl.className = "result-text error";
      }
    });
}