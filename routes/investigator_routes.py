from fastapi import APIRouter, Depends, Header, HTTPException

from auth.investigator import (
    authenticate_investigator,
    create_investigator_session,
    end_investigator_session,
    create_investigator,
    update_investigator,
)
from database.database import get_all_investigators
from forensic.evidence import record_api_interaction, record_forensic_event
from routes.dependencies import get_current_investigator, require_lead_investigator
from routes.models import (
    InvestigatorLoginRequest,
    InvestigatorCreateRequest,
    InvestigatorUpdateRequest,
)

router = APIRouter()


@router.post("/investigators/login")
def investigator_login(request: InvestigatorLoginRequest):
    investigator = authenticate_investigator(request.username, request.password)
    if investigator is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session_token = create_investigator_session(investigator["investigator_id"])

    return {
        "session_token": session_token,
        "investigator_id": investigator["investigator_id"],
        "display_name": investigator["display_name"],
        "role": investigator["role"],
    }


@router.post("/investigators/logout")
def investigator_logout(
    x_investigator_session: str | None = Header(
        default=None, alias="X-Investigator-Session"
    )
):
    if x_investigator_session:
        end_investigator_session(x_investigator_session)
    return {"status": "ok"}


@router.get("/investigators/me")
def investigator_me(investigator: dict = Depends(get_current_investigator)):
    return {
        "investigator_id": investigator["investigator_id"],
        "display_name": investigator["display_name"],
        "role": investigator["role"],
    }


@router.get("/investigators")
def investigators_list():
    return get_all_investigators()


@router.post("/investigators")
def investigators_create(
    request: InvestigatorCreateRequest,
    investigator: dict = Depends(require_lead_investigator),
):
    try:
        created = create_investigator(
            display_name=request.display_name,
            username=request.username,
            password=request.password,
            role=request.role,
            status=request.status,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint="/investigators",
        response_status=200,
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="INVESTIGATOR_CREATED",
        details={
            "investigator_id": created["investigator_id"],
            "display_name": created["display_name"],
            "role": created["role"],
            "status": created["status"],
            "created_by": investigator["investigator_id"],
        },
    )

    return {
        "investigator_id": created["investigator_id"],
        "display_name": created["display_name"],
        "username": created["username"],
        "role": created["role"],
        "status": created["status"],
    }


@router.patch("/investigators/{investigator_id}")
def investigators_update(
    investigator_id: str,
    request: InvestigatorUpdateRequest,
    investigator: dict = Depends(require_lead_investigator),
):
    try:
        updated = update_investigator(
            investigator_id,
            display_name=request.display_name,
            role=request.role,
            status=request.status,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if updated is None:
        raise HTTPException(status_code=404, detail="Investigator not found")

    interaction_id = record_api_interaction(
        http_method="PATCH",
        endpoint=f"/investigators/{investigator_id}",
        response_status=200,
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="INVESTIGATOR_UPDATED",
        details={
            "investigator_id": updated["investigator_id"],
            "display_name": updated["display_name"],
            "role": updated["role"],
            "status": updated["status"],
            "changed_by": investigator["investigator_id"],
        },
    )

    return {
        "investigator_id": updated["investigator_id"],
        "display_name": updated["display_name"],
        "username": updated["username"],
        "role": updated["role"],
        "status": updated["status"],
    }