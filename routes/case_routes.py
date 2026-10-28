from fastapi import APIRouter, Depends, HTTPException

from cases import (
    create_case,
    reassign_case,
    change_case_status,
    get_case_with_investigator,
    get_all_cases_with_investigators,
    ALLOWED_CASE_STATUSES,
)
from forensic.evidence import record_api_interaction, record_forensic_event
from routes.dependencies import get_current_investigator
from routes.models import CaseCreateRequest, CaseReassignRequest, CaseStatusRequest

router = APIRouter()


@router.post("/cases")
def cases_create(
    request: CaseCreateRequest, investigator: dict = Depends(get_current_investigator)
):
    assigned_id = request.assigned_investigator_id or investigator["investigator_id"]

    case = create_case(
        title=request.title,
        assigned_investigator_id=assigned_id,
        account_id=request.account_id,
        finding_id=request.finding_id,
        description=request.description,
    )

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint="/cases",
        response_status=200,
        account_id=request.account_id,
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CASE_CREATED",
        account_id=request.account_id,
        details={
            "case_id": case["case_id"],
            "case_reference": case["case_reference"],
            "title": case["title"],
            "assigned_investigator_id": assigned_id,
            "finding_id": request.finding_id,
            "created_by": investigator["investigator_id"],
        },
    )

    return case


@router.get("/cases")
def cases_list():
    return get_all_cases_with_investigators()


@router.get("/cases/{case_id}")
def cases_detail(case_id: str):
    case = get_case_with_investigator(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/assign")
def cases_reassign(
    case_id: str,
    request: CaseReassignRequest,
    investigator: dict = Depends(get_current_investigator),
):
    existing = get_case_with_investigator(case_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Case not found")

    previous_investigator_id = existing.get("assigned_investigator_id")
    updated = reassign_case(case_id, request.investigator_id)

    interaction_id = record_api_interaction(
        http_method="PATCH",
        endpoint=f"/cases/{case_id}/assign",
        response_status=200,
        account_id=existing.get("account_id"),
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CASE_REASSIGNED",
        account_id=existing.get("account_id"),
        details={
            "case_id": case_id,
            "case_reference": existing["case_reference"],
            "previous_investigator_id": previous_investigator_id,
            "new_investigator_id": request.investigator_id,
            "changed_by": investigator["investigator_id"],
        },
    )

    return updated


@router.patch("/cases/{case_id}/status")
def cases_status_update(
    case_id: str,
    request: CaseStatusRequest,
    investigator: dict = Depends(get_current_investigator),
):
    if request.status not in ALLOWED_CASE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported status. Allowed: {sorted(ALLOWED_CASE_STATUSES)}",
        )

    existing = get_case_with_investigator(case_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Case not found")

    updated = change_case_status(case_id, request.status)

    interaction_id = record_api_interaction(
        http_method="PATCH",
        endpoint=f"/cases/{case_id}/status",
        response_status=200,
        account_id=existing.get("account_id"),
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="CASE_STATUS_CHANGED",
        account_id=existing.get("account_id"),
        details={
            "case_id": case_id,
            "case_reference": existing["case_reference"],
            "old_status": existing["status"],
            "new_status": request.status,
            "changed_by": investigator["investigator_id"],
        },
    )

    return updated