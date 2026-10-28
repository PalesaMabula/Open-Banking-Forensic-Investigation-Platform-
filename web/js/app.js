// ================================================
// Application bootstrap — filters, refresh, and page initialization
// ================================================
function initFilters() {
  ["filter-scenario", "filter-severity", "filter-status"].forEach((id) => {
    document.getElementById(id).addEventListener("change", renderFindingsTable);
  });
}

async function populateAccountDropdowns() {
  const selectIds = [
    "customer-account-id",
    "budgetwise-account-id",
    "insurewise-account-id",
  ];
  let accounts = [];
  try {
    const data = await apiRequest("/sandbox/accounts");
    accounts = data.accounts || [];
  } catch (err) {
    accounts = [];
  }

  selectIds.forEach((id) => {
    const select = document.getElementById(id);
    if (!select) return;
    if (!accounts.length) {
      select.innerHTML =
        '<option value="">No sandbox accounts available</option>';
      return;
    }
    select.innerHTML =
      '<option value="">Select an account…</option>' +
      accounts
        .map(
          (a) =>
            `<option value="${escapeHtml(a.accountId)}">${escapeHtml(
              a.accountName,
            )} — ${escapeHtml(a.accountId)}</option>`,
        )
        .join("");
  });
}

function refreshAll() {
  loadDashboard();
  loadApiCommunication();
  loadFindings();
  loadEvaluation();
  loadCasesList();
  loadInvestigatorsList();
  if (state.currentFindingId) loadInvestigation(state.currentFindingId);
  if (state.lastCustomerAccountId)
    loadCustomerContent(state.lastCustomerAccountId);
  if (state.lastAppAccountId.BudgetWise)
    loadAppStatus(
      "BudgetWise",
      "budgetwise",
      state.lastAppAccountId.BudgetWise,
    );
  if (state.lastAppAccountId.InsureWise)
    loadAppStatus(
      "InsureWise",
      "insurewise",
      state.lastAppAccountId.InsureWise,
    );
}


document.addEventListener("DOMContentLoaded", () => {
  initNav();
  initTheme();
  // ...rest unchanged
  initFilters();
  initEvaluateButton();
  initScenarioButtons();
  initCustomerPage();
  initAppPage("BudgetWise", "budgetwise", ["accounts", "transactions"]);
  initAppPage("InsureWise", "insurewise", ["accounts"]);
  populateAccountDropdowns();
  initInvestigatorAuth();
  initCasesPage();
  initInvestigatorsPage();
  renderInvestigatorBar();
  loadDashboard();
  loadApiCommunication();
  loadFindings();
  loadEvaluation();
  refreshCasesUI();
  showHomeScreen();
});