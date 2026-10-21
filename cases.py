import uuid
from datetime import datetime, timezone

from database.database import (
    count_cases,
    insert_case,
    get_case_by_id,
    get_all_cases,
    update_case_assignment,
    update_case_status,
    get_investigator_by_id,
)

ALLOWED_CASE_STATUSES = {"OPEN", "IN_PROGRESS", "CLOSED"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_case_reference() -> str:
    """
    Deterministic, human-readable case reference: CASE-{year}-{sequence},
    sequence derived from the current total case count + 1. Not
    collision-proof under concurrent writes, but adequate for this
    single-process prototype.
    """
    year = datetime.now(timezone.utc).year
    sequence = count_cases() + 1
    return f"CASE-{year}-{sequence:04d}"


def create_case(
    title: str,
    assigned_investigator_id: str | None,
    account_id: str | None = None,
    finding_id: str | None = None,
    description: str | None = None,
) -> dict:
    case_id = str(uuid.uuid4())
    now = _utc_now_iso()

    case = {
        "case_id": case_id,
        "case_reference": generate_case_reference(),
        "title": title,
        "status": "OPEN",
        "assigned_investigator_id": assigned_investigator_id,
        "account_id": account_id,
        "finding_id": finding_id,
        "description": description,
        "created_at": now,
        "updated_at": now,
    }
    insert_case(case)
    return get_case_by_id(case_id)


def reassign_case(case_id: str, new_investigator_id: str) -> dict | None:
    """
    Reassigns a case to a different investigator. This is a case-level
    administrative change, NOT a custody TRANSFERRED action — evidence
    custody is untouched by who is assigned to the case. If a future
    step introduces an explicit "transfer evidence to investigator X"
    action, that is where a real custody TRANSFERRED event belongs.
    """
    return update_case_assignment(case_id, new_investigator_id, _utc_now_iso())


def change_case_status(case_id: str, new_status: str) -> dict | None:
    if new_status not in ALLOWED_CASE_STATUSES:
        raise ValueError(f"Unsupported case status: {new_status}")
    return update_case_status(case_id, new_status, _utc_now_iso())


def get_case_with_investigator(case_id: str) -> dict | None:
    case = get_case_by_id(case_id)
    if case is None:
        return None

    investigator = None
    if case.get("assigned_investigator_id"):
        inv = get_investigator_by_id(case["assigned_investigator_id"])
        if inv:
            investigator = {
                "investigator_id": inv["investigator_id"],
                "display_name": inv["display_name"],
                "role": inv["role"],
            }

    return {**case, "assigned_investigator": investigator}


def get_all_cases_with_investigators() -> list[dict]:
    cases = get_all_cases()
    results = []
    for case in cases:
        investigator_name = None
        if case.get("assigned_investigator_id"):
            inv = get_investigator_by_id(case["assigned_investigator_id"])
            if inv:
                investigator_name = inv["display_name"]
        results.append(
            {
                "case_id": case["case_id"],
                "case_reference": case["case_reference"],
                "title": case["title"],
                "status": case["status"],
                "assigned_investigator_name": investigator_name,
                "account_id": case.get("account_id"),
                "finding_id": case.get("finding_id"),
                "created_at": case["created_at"],
                "updated_at": case["updated_at"],
            }
        )
    return results
