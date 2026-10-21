// ================================================
// Application bootstrap — filters, refresh, and page initialization
// ================================================
function initFilters() {
  ["filter-scenario", "filter-severity", "filter-status"].forEach((id) => {
    document.getElementById(id).addEventListener("change", renderFindingsTable);
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