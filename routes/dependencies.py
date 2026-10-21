from fastapi import Depends, Header, HTTPException

from auth.authentication import (
    get_baseline_context,
    authenticate_and_issue_token,
    get_app_credentials,
    default_context_for_app,
    get_active_app_token,
    set_active_app_token,
)
from auth.investigator import get_investigator_from_session
from database.database import get_application_by_name


def get_current_investigator(
    x_investigator_session: str | None = Header(
        default=None, alias="X-Investigator-Session"
    ),
) -> dict:
    """
    Resolves the authenticated investigator from the session header.
    Raises 401 if missing or invalid — this is the ONLY path by which
    an investigator identity enters the system; it is never accepted
    as free-typed request data.
    """
    if x_investigator_session is None:
        raise HTTPException(status_code=401, detail="Investigator session required")

    investigator = get_investigator_from_session(x_investigator_session)
    if investigator is None:
        raise HTTPException(
            status_code=401, detail="Invalid or expired investigator session"
        )

    return investigator


def require_lead_investigator(
    investigator: dict = Depends(get_current_investigator),
) -> dict:
    """
    Step 12B role gate: only a Lead Investigator may create or edit
    investigator accounts. A Forensic Analyst can still sign in, work
    cases, and act on evidence — just not manage other investigators.
    """
    if investigator["role"] != "Lead Investigator":
        raise HTTPException(
            status_code=403,
            detail="Only a Lead Investigator can manage investigator accounts",
        )
    return investigator

#returns a valid token for the given applicationand  authenticating with the app credentials
def authenticate_app(app_name: str, account_id: str | None = None) -> tuple[str, str]:
    
    default_context = default_context_for_app(app_name)

    existing_token = get_active_app_token(app_name)
    if existing_token is not None:
        return existing_token, default_context

    credentials = get_app_credentials(app_name)
    if credentials is None:
        raise HTTPException(status_code=404, detail="Unknown application")

    context = default_context
    application = get_application_by_name(app_name)
    if application is not None:
        baseline = get_baseline_context(application["application_id"])
        if baseline is not None:
            context = baseline

    client_id, client_secret = credentials
    auth_result = authenticate_and_issue_token(
        client_id, client_secret, context, account_id=account_id
    )
    if not auth_result.get("success"):
        raise HTTPException(
            status_code=401, detail=f"{app_name} could not authenticate internally"
        )

    set_active_app_token(app_name, auth_result["raw_token"])
    return auth_result["raw_token"], context