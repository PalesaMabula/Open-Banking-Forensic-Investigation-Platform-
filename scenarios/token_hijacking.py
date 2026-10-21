from auth.authentication import (
    authenticate_and_issue_token,
    validate_access_token,
    get_baseline_context,
)
from database.database import get_application_by_name
from banking.access import access_accounts

HIJACK_CONTEXT = "UNKNOWN-DEVICE-02"
FALLBACK_CONTEXT = "TPP-PRIMARY-DEVICE"


def run_token_hijacking_scenario(
    client_id: str, client_secret: str, account_id: str | None = None
) -> dict:
    """
    Controlled simulation: mints ONE fresh token for this run, uses it
    once from the application's normal established context, then
    replays the SAME token from a different simulated context. A new
    token per scenario run keeps each run's context history clean —
    no dedup logic needed to avoid retriggering on old context history.
    No second token is ever issued for the replay step itself.
    """
    application = get_application_by_name_from_credentials(client_id)
    normal_context = FALLBACK_CONTEXT
    if application is not None:
        baseline = get_baseline_context(application["application_id"])
        if baseline is not None:
            normal_context = baseline

    auth_result = authenticate_and_issue_token(
        client_id, client_secret, normal_context, account_id=account_id
    )
    if not auth_result.get("success"):
        return {
            "scenario": "TOKEN_HIJACKING",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Authentication failed; cannot run scenario",
        }

    raw_token = auth_result["raw_token"]
    token = validate_access_token(raw_token)
    if token is None:
        return {
            "scenario": "TOKEN_HIJACKING",
            "executed": False,
            "detected": False,
            "finding_id": None,
            "detail": "Token could not be validated after issuance",
        }

    access_accounts(token, normal_context, account_id=account_id)
    second_access = access_accounts(token, HIJACK_CONTEXT, account_id=account_id)

    if not second_access.get("success"):
        return {
            "scenario": "TOKEN_HIJACKING",
            "executed": True,
            "detected": False,
            "finding_id": None,
            "detail": "Access was not successful; this application may not have an "
            "authorized 'accounts' consent for this account yet.",
        }

    return {
        "scenario": "TOKEN_HIJACKING",
        "executed": True,
        "detected": bool(second_access.get("hijack_finding_id")),
        "finding_id": second_access.get("hijack_finding_id"),
    }


def get_application_by_name_from_credentials(client_id: str):
    """
    Looks up the application row matching this client_id — used only
    to find its established baseline context for the "normal" step.
    """
    from database.database import get_all_applications

    for app in get_all_applications():
        if app["client_id"] == client_id:
            return app
    return None
