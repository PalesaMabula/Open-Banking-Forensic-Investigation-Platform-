import json

from fastapi import APIRouter, Depends, HTTPException

from database.database import (
    get_api_interactions,
    get_forensic_events,
    get_forensic_event_by_id,
)
from forensic.custody import (
    record_custody_event,
    get_custody_events,
    verify_custody_chain,
    check_single_event_integrity,
    ALLOWED_ACTIONS,
)
from forensic.detection import get_findings, get_finding_by_id, update_finding_status
from forensic.evaluation import (
    evaluate_finding,
    evaluate_all_findings,
    get_metrics,
    get_metrics_for_finding,
    get_evaluation_summary,
)
from forensic.evidence import record_api_interaction, record_forensic_event
from forensic.integrity import verify_evidence_chain
from forensic.investigation import (
    get_investigation_summary,
    build_timeline,
    get_related_evidence,
    get_custody_history_for_finding,
    get_account_investigation,
    ALLOWED_FINDING_STATUSES,
)
from routes.dependencies import get_current_investigator
from routes.models import (
    CustodyActionRequest,
    FindingStatusUpdateRequest,
    MarkAnalysedRequest,
    EvidenceActionRequest,
)

router = APIRouter()


#all interactions and events are recorded in the forensic database for audit and investigation purposes


@router.get("/forensics/interactions")
def forensics_interactions():
    return get_api_interactions()


@router.get("/forensics/events")
def forensics_events():
    return get_forensic_events()


@router.get("/forensics/integrity")
def forensics_integrity():
    return verify_evidence_chain()


@router.get("/forensics/public-key")
def forensics_public_key():
    """Publishes the Ed25519 public key so evidence signatures can be
    verified independently of this platform."""
    from forensic.signing import get_public_key_hex

    return {"algorithm": "Ed25519", "public_key": get_public_key_hex()}




#chain of custody 
@router.get("/forensics/custody-integrity")
def forensics_custody_integrity():
    return verify_custody_chain()


@router.get("/forensics/custody")
def forensics_custody_all():
    return get_custody_events()


@router.get("/forensics/custody/{evidence_id}")
def forensics_custody_for_evidence(evidence_id: str):
    forensic_event = get_forensic_event_by_id(evidence_id)
    if forensic_event is None:
        raise HTTPException(status_code=404, detail="Forensic event not found")

    return get_custody_events(evidence_id=evidence_id)


@router.post("/forensics/custody/{evidence_id}")
def forensics_custody_action(evidence_id: str, request: CustodyActionRequest):
    if request.action not in ALLOWED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported custody action. Allowed: {sorted(ALLOWED_ACTIONS)}",
        )

    forensic_event = get_forensic_event_by_id(evidence_id)
    if forensic_event is None:
        raise HTTPException(status_code=404, detail="Forensic event not found")

    integrity_status = check_single_event_integrity(evidence_id)

    return record_custody_event(
        evidence_id=evidence_id,
        actor=request.actor,
        action=request.action,
        evidence_hash=forensic_event.get("event_hash"),
        from_holder=request.from_holder,
        to_holder=request.to_holder,
        reason=request.reason,
        integrity_status=integrity_status,
    )




#findins 
@router.get("/forensics/findings")
def forensics_findings():
    findings = get_findings()
    return [
        {
            "finding_id": f["finding_id"],
            "scenario_type": f["scenario_type"],
            "severity": f["severity"],
            "status": f["status"],
            "detected_at": f["detected_at"],
            "application_id": f.get("application_id"),
            "account_id": f.get("account_id"),
        }
        for f in findings
    ]


@router.get("/forensics/findings/{finding_id}")
def forensics_finding_detail(finding_id: str):
    finding = get_finding_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/forensics/findings/{finding_id}/status")
def forensics_finding_status_update(
    finding_id: str, request: FindingStatusUpdateRequest
):
    if request.status not in ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported status. Allowed: {sorted(ALLOWED_FINDING_STATUSES)}",
        )

    existing = get_finding_by_id(finding_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = existing["status"]
    updated = update_finding_status(finding_id, request.status)

    interaction_id = record_api_interaction(
        http_method="PATCH",
        endpoint=f"/forensics/findings/{finding_id}/status",
        response_status=200,
        source="INVESTIGATOR",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="FINDING_STATUS_CHANGED",
        details={
            "finding_id": finding_id,
            "old_status": old_status,
            "new_status": request.status,
            "actor": request.actor,
        },
    )

    return updated



#investigations 
@router.get("/forensics/investigations/{finding_id}")
def investigation_summary(finding_id: str):
    summary = get_investigation_summary(finding_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return summary


@router.get("/forensics/investigations/{finding_id}/timeline")
def investigation_timeline(finding_id: str):
    timeline = build_timeline(finding_id)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return timeline


@router.get("/forensics/investigations/{finding_id}/evidence")
def investigation_evidence(finding_id: str):
    evidence = get_related_evidence(finding_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return evidence


@router.get("/forensics/investigations/{finding_id}/custody")
def investigation_custody(finding_id: str):
    custody = get_custody_history_for_finding(finding_id)
    if custody is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return custody


@router.post("/forensics/investigations/{finding_id}/mark-analysed")
def investigation_mark_analysed(finding_id: str, request: MarkAnalysedRequest):
    finding = get_finding_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    related_event_ids = json.loads(finding.get("related_event_ids_json") or "[]")
    records = []

    for event_id in related_event_ids:
        event = get_forensic_event_by_id(event_id)
        if event is None:
            continue

        integrity_status = check_single_event_integrity(event_id)
        record = record_custody_event(
            evidence_id=event_id,
            actor=request.actor,
            action="ANALYSED",
            evidence_hash=event.get("event_hash"),
            from_holder="OBFIR_EVIDENCE_STORE",
            to_holder=request.actor,
            reason=request.reason or "Investigation analysis",
            integrity_status=integrity_status,
        )
        records.append(record)

    return {
        "finding_id": finding_id,
        "analysed_event_count": len(records),
        "custody_records": records,
    }




# forensic evalusation metric 
@router.post("/forensics/evaluate/{finding_id}")
def evaluate_one_finding(finding_id: str):
    result = evaluate_finding(finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.post("/forensics/evaluate")
def evaluate_all():
    return evaluate_all_findings()


@router.get("/forensics/metrics")
def forensics_metrics():
    return get_metrics()


@router.get("/forensics/metrics/{finding_id}")
def forensics_metrics_for_finding(finding_id: str):
    finding = get_finding_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return get_metrics_for_finding(finding_id)


@router.get("/forensics/evaluation/summary")
def forensics_evaluation_summary():
    return get_evaluation_summary()


# ==================================================
# Forensics: dashboard summary
# ==================================================


@router.get("/forensics/dashboard/summary")
def forensics_dashboard_summary():
    evidence_integrity = verify_evidence_chain()
    custody_integrity = verify_custody_chain()

    findings = get_findings()
    open_findings = sum(1 for f in findings if f["status"] == "OPEN")
    critical_findings = sum(1 for f in findings if f["severity"] == "CRITICAL")

    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    scenario_types = [
        "CREDENTIAL_THEFT",
        "TOKEN_HIJACKING",
        "CONSENT_BASED_FRAUD",
        "CROSS_BORDER_DATA_EXFILTRATION",
    ]

    all_metrics = get_metrics()
    evaluated_finding_ids_by_scenario: dict = {}
    for m in all_metrics:
        evaluated_finding_ids_by_scenario.setdefault(m.get("scenario_type"), set()).add(
            m["finding_id"]
        )

    by_scenario = {}
    for scenario_type in scenario_types:
        scenario_findings = [f for f in findings if f["scenario_type"] == scenario_type]
        if not scenario_findings:
            by_scenario[scenario_type] = {"count": 0}
            continue

        highest_severity = max(
            scenario_findings, key=lambda f: severity_rank.get(f["severity"], 0)
        )["severity"]
        most_recent = max(scenario_findings, key=lambda f: f["detected_at"])[
            "detected_at"
        ]
        evaluated_count = len(
            evaluated_finding_ids_by_scenario.get(scenario_type, set())
        )

        by_scenario[scenario_type] = {
            "count": len(scenario_findings),
            "highest_severity": highest_severity,
            "most_recent_detected_at": most_recent,
            "evaluated_count": evaluated_count,
        }

    evaluation_summary = get_evaluation_summary()

    return {
        "evidence_integrity": evidence_integrity,
        "custody_integrity": custody_integrity,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "by_scenario": by_scenario,
        "evaluation_overall": evaluation_summary.get("overall", {}),
    }


# ==================================================
# Authenticated investigator evidence actions
# ==================================================


@router.post("/forensics/evidence/{event_id}/access")
def evidence_access(
    event_id: str,
    request: EvidenceActionRequest,
    investigator: dict = Depends(get_current_investigator),
):
    event = get_forensic_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    integrity_status = check_single_event_integrity(event_id)

    return record_custody_event(
        evidence_id=event_id,
        actor=investigator["investigator_id"],
        action="ACCESSED",
        evidence_hash=event.get("event_hash"),
        from_holder="OBFIR_EVIDENCE_STORE",
        to_holder=investigator["investigator_id"],
        reason=request.reason or "Evidence opened for investigation",
        integrity_status=integrity_status,
    )


@router.post("/forensics/evidence/{event_id}/verify")
def evidence_verify(
    event_id: str,
    request: EvidenceActionRequest,
    investigator: dict = Depends(get_current_investigator),
):
    event = get_forensic_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    integrity_status = check_single_event_integrity(event_id)

    custody_record = record_custody_event(
        evidence_id=event_id,
        actor=investigator["investigator_id"],
        action="VERIFIED",
        evidence_hash=event.get("event_hash"),
        from_holder="OBFIR_EVIDENCE_STORE",
        to_holder=investigator["investigator_id"],
        reason=request.reason or "Evidence integrity verification",
        integrity_status=integrity_status,
    )

    return {"integrity_status": integrity_status, "custody_record": custody_record}


@router.post("/forensics/evidence/{event_id}/analyse")
def evidence_analyse(
    event_id: str,
    request: EvidenceActionRequest,
    investigator: dict = Depends(get_current_investigator),
):
    event = get_forensic_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    integrity_status = check_single_event_integrity(event_id)

    return record_custody_event(
        evidence_id=event_id,
        actor=investigator["investigator_id"],
        action="ANALYSED",
        evidence_hash=event.get("event_hash"),
        from_holder="OBFIR_EVIDENCE_STORE",
        to_holder=investigator["investigator_id"],
        reason=request.reason or "Forensic analysis completed",
        integrity_status=integrity_status,
    )


@router.get("/forensics/account/{account_id}/investigation")
def forensics_account_investigation(
    account_id: str, investigator: dict = Depends(get_current_investigator)
):
    return get_account_investigation(account_id)


@router.post("/forensics/investigations/{finding_id}/auto-access")
def investigation_auto_access(
    finding_id: str, investigator: dict = Depends(get_current_investigator)
):
    """
    Records an ACCESSED custody event for each of this finding's
    related evidence items — but ONLY the first time this specific
    investigator accesses each specific evidence item. If this
    investigator already has an ACCESSED record for a given
    evidence_id, nothing new is created for that item. This is what
    prevents meaningless duplicate ACCESSED records from page
    refreshes, tab switches, or reopening the same investigation.
    """
    finding = get_finding_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    related_event_ids = json.loads(finding.get("related_event_ids_json") or "[]")
    newly_recorded = []

    for event_id in related_event_ids:
        event = get_forensic_event_by_id(event_id)
        if event is None:
            continue

        already_accessed = any(
            c["action"] == "ACCESSED" and c["actor"] == investigator["investigator_id"]
            for c in get_custody_events(evidence_id=event_id)
        )
        if already_accessed:
            continue

        integrity_status = check_single_event_integrity(event_id)
        record = record_custody_event(
            evidence_id=event_id,
            actor=investigator["investigator_id"],
            action="ACCESSED",
            evidence_hash=event.get("event_hash"),
            from_holder="OBFIR_EVIDENCE_STORE",
            to_holder=investigator["investigator_id"],
            reason="Evidence accessed for forensic examination",
            integrity_status=integrity_status,
        )
        newly_recorded.append(record)

    return {"finding_id": finding_id, "newly_recorded_count": len(newly_recorded)}