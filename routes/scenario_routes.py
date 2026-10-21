from fastapi import APIRouter, HTTPException

from auth.authentication import get_app_credentials
from routes.dependencies import authenticate_app
from routes.models import (
    CredentialTheftScenarioRequest,
    TokenHijackingScenarioRequest,
    ConsentFraudScenarioRequest,
    CrossBorderScenarioRequest,
    ScenarioAccountBody,
)
from scenarios.credential_theft import run_credential_theft_scenario
from scenarios.token_hijacking import run_token_hijacking_scenario
from scenarios.consent_fraud import run_consent_fraud_scenario
from scenarios.cross_border import run_cross_border_scenario

router = APIRouter()


#scenarios


@router.post("/scenarios/credential-theft")
def scenario_credential_theft(request: CredentialTheftScenarioRequest):
    return run_credential_theft_scenario(request.client_id, request.client_secret)


@router.post("/scenarios/token-hijacking")
def scenario_token_hijacking(request: TokenHijackingScenarioRequest):
    return run_token_hijacking_scenario(request.client_id, request.client_secret)


@router.post("/scenarios/consent-fraud")
def scenario_consent_fraud(request: ConsentFraudScenarioRequest):
    return run_consent_fraud_scenario(
        request.access_token, request.account_id, request.customer_id
    )


@router.post("/scenarios/cross-border")
def scenario_cross_border(request: CrossBorderScenarioRequest):
    return run_cross_border_scenario(request.access_token)




@router.post("/scenarios/credential-theft/{app_name}")
def scenario_credential_theft_for_app(app_name: str, request: ScenarioAccountBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")
    credentials = get_app_credentials(app_name)
    if credentials is None:
        raise HTTPException(status_code=404, detail="Unknown application")
    client_id, client_secret = credentials
    return run_credential_theft_scenario(
        client_id, client_secret, account_id=request.account_id
    )


@router.post("/scenarios/token-hijacking/{app_name}")
def scenario_token_hijacking_for_app(app_name: str, request: ScenarioAccountBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")
    credentials = get_app_credentials(app_name)
    if credentials is None:
        raise HTTPException(status_code=404, detail="Unknown application")
    client_id, client_secret = credentials
    return run_token_hijacking_scenario(
        client_id, client_secret, account_id=request.account_id
    )


@router.post("/scenarios/consent-fraud/{app_name}")
def scenario_consent_fraud_for_app(app_name: str, request: ScenarioAccountBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")
    raw_token, _ = authenticate_app(app_name, account_id=request.account_id)
    return run_consent_fraud_scenario(raw_token, request.account_id)


@router.post("/scenarios/cross-border/{app_name}")
def scenario_cross_border_for_app(app_name: str, request: ScenarioAccountBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")
    raw_token, _ = authenticate_app(app_name, account_id=request.account_id)
    return run_cross_border_scenario(raw_token, account_id=request.account_id)