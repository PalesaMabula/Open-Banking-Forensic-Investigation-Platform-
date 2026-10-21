import json
import sqlite3
from datetime import datetime, timezone

from database.database import get_connection, get_forensic_event_by_id
from forensic.detection import get_finding_by_id, get_findings
from forensic.custody import check_single_event_integrity, verify_custody_chain


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def _safe_details(event: dict) -> dict:
    try:
        return json.loads(event.get("details_json") or "{}")
    except (TypeError, ValueError):
        return {}


def _get_related_events(finding: dict) -> list[dict]:
    try:
        related_ids = json.loads(finding.get("related_event_ids_json") or "[]")
    except (TypeError, ValueError):
        related_ids = []

    events = []
    for event_id in related_ids:
        event = get_forensic_event_by_id(event_id)
        if event:
            events.append(event)
    return events



#store evulations metrics 
def _store_metric(
    finding_id: str,
    scenario_type: str,
    metric_name: str,
    metric_value: float | None,
    metric_unit: str,
    details: dict,
) -> None:
    
    metric_id = f"{finding_id}:{metric_name}"
    calculated_at = _utc_now_iso()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO evaluation_metrics (
            metric_id, finding_id, scenario_type, metric_name,
            metric_value, metric_unit, calculated_at, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id, metric_name) DO UPDATE SET
            metric_value = excluded.metric_value,
            metric_unit = excluded.metric_unit,
            calculated_at = excluded.calculated_at,
            details_json = excluded.details_json
        """,
        (
            metric_id,
            finding_id,
            scenario_type,
            metric_name,
            metric_value,
            metric_unit,
            calculated_at,
            json.dumps(details),
        ),
    )
    conn.commit()
    conn.close()


def get_metrics() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evaluation_metrics ORDER BY calculated_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_metrics_for_finding(finding_id: str) -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM evaluation_metrics WHERE finding_id = ?", (finding_id,)
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows



#detection latency is the time between the trigger event and the detection of the finding
def _find_trigger_event(finding: dict, related_events: list[dict]) -> dict | None:
    """
    Identifies the event representing the START of suspicious activity
    — not simply the first related event. See section G of the Step 10
    response for the per-scenario rule.
    """
    scenario_type = finding.get("scenario_type")

    if scenario_type == "CREDENTIAL_THEFT":
        candidates = [e for e in related_events if e["event_type"] == "TOKEN_ISSUED"]
        return candidates[-1] if candidates else None

    if scenario_type == "TOKEN_HIJACKING":
        candidates = [
            e
            for e in related_events
            if e["event_type"] in ("ACCOUNT_DATA_ACCESSED", "TRANSACTION_DATA_ACCESSED")
        ]
        candidates.sort(key=lambda e: e["timestamp"])
        return candidates[-1] if candidates else None

    if scenario_type == "CONSENT_BASED_FRAUD":
        candidates = [
            e for e in related_events if e["event_type"] == "CONSENT_PERMISSION_DENIED"
        ]
        return candidates[-1] if candidates else None

    if scenario_type == "CROSS_BORDER_DATA_EXFILTRATION":
        for e in related_events:
            if e["event_type"] not in (
                "ACCOUNT_DATA_ACCESSED",
                "TRANSACTION_DATA_ACCESSED",
            ):
                continue
            details = _safe_details(e)
            if (
                details.get("destination_country")
                and details["destination_country"] != "ZA"
            ):
                return e
        return None

    return None


def calculate_detection_latency(finding_id: str) -> dict:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return {
            "metric": "DETECTION_LATENCY",
            "status": "UNAVAILABLE",
            "reason": "Finding not found",
        }

    related_events = _get_related_events(finding)
    trigger_event = _find_trigger_event(finding, related_events)

    if trigger_event is None:
        return {
            "metric": "DETECTION_LATENCY",
            "status": "UNAVAILABLE",
            "reason": "Trigger event could not be identified from related evidence",
        }

    try:
        trigger_time = _parse_iso(trigger_event["timestamp"])
        detected_time = _parse_iso(finding["detected_at"])
    except (TypeError, ValueError):
        return {
            "metric": "DETECTION_LATENCY",
            "status": "UNAVAILABLE",
            "reason": "Could not parse timestamps",
        }

    latency_ms = (detected_time - trigger_time).total_seconds() * 1000

    details = {
        "trigger_event_id": trigger_event["event_id"],
        "trigger_event_type": trigger_event["event_type"],
        "trigger_timestamp": trigger_event["timestamp"],
        "detected_at": finding["detected_at"],
    }

    if latency_ms < 0:
        return {
            "metric": "DETECTION_LATENCY",
            "status": "ISSUE",
            "reason": "Calculated latency is negative — detected_at precedes trigger timestamp",
            "metric_value": latency_ms,
            "metric_unit": "milliseconds",
            "details": details,
        }

    return {
        "metric": "DETECTION_LATENCY",
        "status": "OK",
        "metric_value": round(latency_ms, 3),
        "metric_unit": "milliseconds",
        "details": details,
    }


#log completeness is the percentage of expected forensic events that were captured for a given finding


def _has_context_variant(related_events: list[dict], first: bool) -> bool:
    access_events = sorted(
        [
            e
            for e in related_events
            if e["event_type"] in ("ACCOUNT_DATA_ACCESSED", "TRANSACTION_DATA_ACCESSED")
        ],
        key=lambda e: e["timestamp"],
    )
    if not access_events:
        return False

    contexts = [_safe_details(e).get("client_context") for e in access_events]

    if first:
        return contexts[0] is not None

    return any(c != contexts[0] for c in contexts[1:])


def _category_satisfied(
    category_key: str, related_events: list[dict], finding: dict
) -> bool:
    event_types = {e["event_type"] for e in related_events}

    def has_detail(field_name: str) -> bool:
        return any(field_name in _safe_details(e) for e in related_events)

    checks = {
        "authentication_activity": bool(
            event_types & {"TOKEN_ISSUED", "AUTHENTICATION_SUCCEEDED"}
        ),
        "client_context_recorded": has_detail("client_context")
        or "NEW_CLIENT_CONTEXT_OBSERVED" in event_types,
        "token_issuance": "TOKEN_ISSUED" in event_types,
        "suspicious_context_activity": "NEW_CLIENT_CONTEXT_OBSERVED" in event_types,
        "credential_theft_detection": "CREDENTIAL_THEFT_DETECTED" in event_types,
        "legitimate_token_use": _has_context_variant(related_events, first=True),
        "replayed_token_use": _has_context_variant(related_events, first=False),
        "token_fingerprint_recorded": has_detail("token_fingerprint"),
        "token_hijacking_detection": "TOKEN_HIJACKING_DETECTED" in event_types,
        "consent_creation": "CONSENT_CREATED" in event_types,
        "consent_authorization": "CONSENT_AUTHORIZED" in event_types,
        "allowed_permissions_recorded": has_detail("permissions"),
        "unauthorized_access_attempt": "CONSENT_PERMISSION_DENIED" in event_types,
        "consent_fraud_detection": "CONSENT_BASED_FRAUD_DETECTED" in event_types,
        "protected_data_access": bool(
            event_types & {"ACCOUNT_DATA_ACCESSED", "TRANSACTION_DATA_ACCESSED"}
        ),
        "authorized_consent_context": has_detail("consent_id"),
        "simulated_destination_recorded": has_detail("destination_country"),
        "cross_border_detection": "CROSS_BORDER_EXFILTRATION_DETECTED" in event_types,
        "finding_recorded": finding is not None,
    }

    return checks.get(category_key, False)


SCENARIO_REQUIREMENTS = {
    "CREDENTIAL_THEFT": [
        "authentication_activity",
        "client_context_recorded",
        "token_issuance",
        "suspicious_context_activity",
        "credential_theft_detection",
        "finding_recorded",
    ],
    "TOKEN_HIJACKING": [
        "token_issuance",
        "legitimate_token_use",
        "replayed_token_use",
        "token_fingerprint_recorded",
        "client_context_recorded",
        "token_hijacking_detection",
        "finding_recorded",
    ],
    "CONSENT_BASED_FRAUD": [
        "consent_creation",
        "consent_authorization",
        "allowed_permissions_recorded",
        "unauthorized_access_attempt",
        "consent_fraud_detection",
        "finding_recorded",
    ],
    "CROSS_BORDER_DATA_EXFILTRATION": [
        "protected_data_access",
        "authorized_consent_context",
        "simulated_destination_recorded",
        "cross_border_detection",
        "finding_recorded",
    ],
}


def calculate_log_completeness(finding_id: str) -> dict:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return {
            "metric": "LOG_COMPLETENESS",
            "status": "UNAVAILABLE",
            "reason": "Finding not found",
        }

    scenario_type = finding.get("scenario_type")
    required_categories = SCENARIO_REQUIREMENTS.get(scenario_type)

    if required_categories is None:
        return {
            "metric": "LOG_COMPLETENESS",
            "status": "UNAVAILABLE",
            "reason": f"No evidence checklist defined for scenario_type '{scenario_type}'",
        }

    related_events = _get_related_events(finding)

    captured = [
        c
        for c in required_categories
        if _category_satisfied(c, related_events, finding)
    ]
    missing = [c for c in required_categories if c not in captured]

    completeness_percent = round((len(captured) / len(required_categories)) * 100, 2)

    return {
        "metric": "LOG_COMPLETENESS",
        "status": "OK",
        "metric_value": completeness_percent,
        "metric_unit": "percent",
        "details": {
            "expected_categories": required_categories,
            "captured_categories": captured,
            "missing_categories": missing,
        },
    }


#evidence preservations rate is related to events not being tampered with and the integrity of the evidence being preserved

def calculate_evidence_preservation_rate(finding_id: str) -> dict:
    """
    Uses only forensic_events referenced by related_event_ids_json —
    these are the integrity-protected items. The finding row itself is
    NOT counted, since forensic_findings is not part of the SHA-256
    hash chain; it is a derived record, not preserved primary evidence.
    """
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return {
            "metric": "EVIDENCE_PRESERVATION_RATE",
            "status": "UNAVAILABLE",
            "reason": "Finding not found",
        }

    try:
        related_ids = json.loads(finding.get("related_event_ids_json") or "[]")
    except (TypeError, ValueError):
        related_ids = []

    if not related_ids:
        return {
            "metric": "EVIDENCE_PRESERVATION_RATE",
            "status": "UNAVAILABLE",
            "reason": "Finding has no related evidence items",
        }

    valid_items, invalid_items, missing_items = [], [], []

    for event_id in related_ids:
        event = get_forensic_event_by_id(event_id)
        if event is None:
            missing_items.append(event_id)
            continue

        status = check_single_event_integrity(event_id)
        if status == "VALID":
            valid_items.append(event_id)
        else:
            invalid_items.append(event_id)

    total = len(related_ids)
    rate_percent = round((len(valid_items) / total) * 100, 2)
    custody_status = verify_custody_chain()

    return {
        "metric": "EVIDENCE_PRESERVATION_RATE",
        "status": "OK",
        "metric_value": rate_percent,
        "metric_unit": "percent",
        "details": {
            "total_evidence_items": total,
            "valid_items": valid_items,
            "invalid_items": invalid_items,
            "missing_items": missing_items,
            "custody_chain_valid": custody_status["valid"],
        },
    }


#all findgs 


def evaluate_finding(finding_id: str) -> dict | None:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return None

    scenario_type = finding["scenario_type"]

    latency_result = calculate_detection_latency(finding_id)
    completeness_result = calculate_log_completeness(finding_id)
    preservation_result = calculate_evidence_preservation_rate(finding_id)

    if latency_result["status"] == "OK":
        _store_metric(
            finding_id,
            scenario_type,
            "DETECTION_LATENCY",
            latency_result["metric_value"],
            latency_result["metric_unit"],
            latency_result["details"],
        )

    if completeness_result["status"] == "OK":
        _store_metric(
            finding_id,
            scenario_type,
            "LOG_COMPLETENESS",
            completeness_result["metric_value"],
            completeness_result["metric_unit"],
            completeness_result["details"],
        )

    if preservation_result["status"] == "OK":
        _store_metric(
            finding_id,
            scenario_type,
            "EVIDENCE_PRESERVATION_RATE",
            preservation_result["metric_value"],
            preservation_result["metric_unit"],
            preservation_result["details"],
        )

    return {
        "finding_id": finding_id,
        "scenario_type": scenario_type,
        "metrics": {
            "detection_latency_ms": (
                latency_result.get("metric_value")
                if latency_result["status"] == "OK"
                else None
            ),
            "detection_latency_status": latency_result["status"],
            "log_completeness_percent": (
                completeness_result.get("metric_value")
                if completeness_result["status"] == "OK"
                else None
            ),
            "log_completeness_status": completeness_result["status"],
            "evidence_preservation_rate_percent": (
                preservation_result.get("metric_value")
                if preservation_result["status"] == "OK"
                else None
            ),
            "evidence_preservation_rate_status": preservation_result["status"],
        },
    }


def evaluate_all_findings() -> list[dict]:
    findings = get_findings()
    results = []
    for finding in findings:
        result = evaluate_finding(finding["finding_id"])
        if result:
            results.append(result)
    return results



#summaries 
def get_evaluation_summary() -> dict:
    all_metrics = get_metrics()

    by_scenario: dict = {}

    for metric in all_metrics:
        scenario_type = metric.get("scenario_type") or "UNKNOWN"
        by_scenario.setdefault(
            scenario_type,
            {
                "DETECTION_LATENCY": [],
                "LOG_COMPLETENESS": [],
                "EVIDENCE_PRESERVATION_RATE": [],
                "finding_ids": set(),
            },
        )
        by_scenario[scenario_type][metric["metric_name"]].append(metric["metric_value"])
        by_scenario[scenario_type]["finding_ids"].add(metric["finding_id"])

    summary = {}
    for scenario_type, data in by_scenario.items():
        latencies = data["DETECTION_LATENCY"]
        completeness = data["LOG_COMPLETENESS"]
        preservation = data["EVIDENCE_PRESERVATION_RATE"]

        summary[scenario_type] = {
            "findings_evaluated": len(data["finding_ids"]),
            "average_detection_latency_ms": (
                round(sum(latencies) / len(latencies), 3) if latencies else None
            ),
            "average_log_completeness_percent": (
                round(sum(completeness) / len(completeness), 2)
                if completeness
                else None
            ),
            "average_evidence_preservation_rate_percent": (
                round(sum(preservation) / len(preservation), 2)
                if preservation
                else None
            ),
        }

    all_finding_ids, all_latencies, all_completeness, all_preservation = (
        set(),
        [],
        [],
        [],
    )
    for metric in all_metrics:
        all_finding_ids.add(metric["finding_id"])
        if metric["metric_name"] == "DETECTION_LATENCY":
            all_latencies.append(metric["metric_value"])
        elif metric["metric_name"] == "LOG_COMPLETENESS":
            all_completeness.append(metric["metric_value"])
        elif metric["metric_name"] == "EVIDENCE_PRESERVATION_RATE":
            all_preservation.append(metric["metric_value"])

    overall = {
        "findings_evaluated": len(all_finding_ids),
        "average_detection_latency_ms": (
            round(sum(all_latencies) / len(all_latencies), 3) if all_latencies else None
        ),
        "average_log_completeness_percent": (
            round(sum(all_completeness) / len(all_completeness), 2)
            if all_completeness
            else None
        ),
        "average_evidence_preservation_rate_percent": (
            round(sum(all_preservation) / len(all_preservation), 2)
            if all_preservation
            else None
        ),
    }

    return {"by_scenario": summary, "overall": overall}
