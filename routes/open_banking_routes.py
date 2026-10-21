import json

from fastapi import APIRouter, HTTPException

from auth.authentication import validate_access_token
from auth.consent import (
    create_consent,
    find_authorized_consent,
    get_consents_for_account,
)
from banking.access import (
    access_accounts,
    access_transactions,
    get_customer_account_view,
)
from database.database import get_all_applications, get_application_by_name
from forensic.evidence import record_api_interaction, record_forensic_event
from routes.dependencies import authenticate_app
from routes.models import AccessRequestCreate, AccountIdBody

router = APIRouter()


@router.get("/open-banking/summary")
def open_banking_summary():
    applications = get_all_applications()
    result_apps = []

    for app_row in applications:
        if app_row["application_name"] not in ("BudgetWise", "InsureWise"):
            continue

        consent = find_authorized_consent(app_row["application_id"], "accounts")
        permissions = json.loads(consent["permissions_json"]) if consent else []

        result_apps.append(
            {
                "application_id": app_row["application_id"],
                "application_name": app_row["application_name"],
                "client_id": app_row["client_id"],
                "status": app_row["status"],
                "consent_id": consent["consent_id"] if consent else None,
                "consent_status": consent["status"] if consent else "NONE",
                "permissions": permissions,
            }
        )

    return {
        "customer_id": "customer-001",
        "customer_display_name": "Customer 001",
        "bank": "Investec Sandbox",
        "connected_applications": len(result_apps),
        "active_consents": sum(
            1 for a in result_apps if a["consent_status"] == "AUTHORIZED"
        ),
        "applications": result_apps,
    }


@router.get("/open-banking/customer/account/{account_id}")
def open_banking_customer_account(account_id: str):
    return get_customer_account_view(account_id)


@router.get("/open-banking/customer/account/{account_id}/access")
def open_banking_customer_access(account_id: str):
    """
    Returns access requests and current access for the given account,
    with application names resolved. Used by the Customer page AND
    the BudgetWise/InsureWise pages (filtered client-side by app name).
    """
    consents = get_consents_for_account(account_id)
    applications = get_all_applications()
    apps_by_id = {a["application_id"]: a["application_name"] for a in applications}

    requests = []
    for c in consents:
        requests.append(
            {
                "consent_id": c["consent_id"],
                "application_id": c["application_id"],
                "application_name": apps_by_id.get(
                    c["application_id"], "Unknown Application"
                ),
                "permissions": json.loads(c["permissions_json"]),
                "status": c["status"],
                "created_at": c["created_at"],
                "authorized_at": c.get("authorized_at"),
            }
        )

    return {"account_id": account_id, "requests": requests}


@router.post("/open-banking/{app_name}/request-access")
def open_banking_request_access(app_name: str, request: AccessRequestCreate):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")

    application = get_application_by_name(app_name)
    if application is None:
        raise HTTPException(status_code=404, detail=f"{app_name} is not registered")

    consent = create_consent(
        application_id=application["application_id"],
        customer_id="customer-001",
        permissions=request.permissions,
        account_id=request.account_id,
    )

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint=f"/open-banking/{app_name}/request-access",
        response_status=200,
        account_id=request.account_id,
        source="LOCAL_CLIENT",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CONSENT_CREATED",
        account_id=request.account_id,
        details={
            "consent_id": consent["consent_id"],
            "application_id": consent["application_id"],
            "customer_id": consent["customer_id"],
            "account_id": consent["account_id"],
            "permissions": request.permissions,
            "status": consent["status"],
        },
    )

    return consent


@router.post("/open-banking/{app_name}/view-account")
def open_banking_view_account(app_name: str, request: AccountIdBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")

    raw_token, context = authenticate_app(app_name, account_id=request.account_id)
    token = validate_access_token(raw_token)
    if token is None:
        raise HTTPException(status_code=401, detail="Token validation failed")

    result = access_accounts(token, context, account_id=request.account_id)

    if not result["success"]:
        return {
            "success": False,
            "status_code": result["status_code"],
            "detail": result.get("detail"),
        }

    return {"success": True, "data": result["data"]}


@router.post("/open-banking/{app_name}/view-transactions")
def open_banking_view_transactions(app_name: str, request: AccountIdBody):
    if app_name not in ("BudgetWise", "InsureWise"):
        raise HTTPException(status_code=404, detail="Unknown application")

    raw_token, context = authenticate_app(app_name, account_id=request.account_id)
    token = validate_access_token(raw_token)
    if token is None:
        raise HTTPException(status_code=401, detail="Token validation failed")

    result = access_transactions(token, context, request.account_id)

    if not result["success"]:
        return {
            "success": False,
            "status_code": result["status_code"],
            "detail": result.get("detail"),
        }

    return {"success": True, "data": result["data"]}