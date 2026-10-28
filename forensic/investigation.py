import json

from database.database import (
    get_forensic_event_by_id,
    get_api_interaction_by_id,
    get_application_by_id,
    get_forensic_events,
    get_api_interactions,
)
from forensic.detection import get_finding_by_id, get_findings
from forensic.custody import (
    get_custody_events,
    check_single_event_integrity,
    verify_custody_chain,
)
from forensic.integrity import verify_evidence_chain
from auth.consent import get_consent, get_consents_for_account

ALLOWED_FINDING_STATUSES = {"OPEN", "REVIEWED", "CLOSED"}


def _safe_details(event: dict) -> dict:
    try:
        return json.loads(event.get("details_json") or "{}")
    except (TypeError, ValueError):
        return {}


def _describe_forensic_event(event: dict) -> str:
    details = _safe_details(event)
    event_type = event.get("event_type", "")

    descriptions = {
        "AUTHENTICATION_SUCCEEDED": f"Application authenticated successfully (context: {details.get('client_context', 'unknown')}).",
        "AUTHENTICATION_FAILED": f"Authentication attempt failed for client_id '{details.get('client_id', 'unknown')}'.",
        "TOKEN_ISSUED": f"Local access token issued (context: {details.get('client_context', 'unknown')}).",
        "NEW_CLIENT_CONTEXT_OBSERVED": (
            f"New client context observed: baseline '{details.get('baseline_context')}', "
            f"new '{details.get('new_context')}'."
        ),
        "CREDENTIAL_THEFT_DETECTED": f"Valid credentials used from suspicious context '{details.get('suspicious_context')}'.",
        "ACCOUNT_DATA_ACCESSED": f"Account data accessed (context: {details.get('client_context', 'unknown')}).",
        "TRANSACTION_DATA_ACCESSED": (
            f"Transaction data accessed for account '{details.get('account_id', 'unknown')}' "
            f"(context: {details.get('client_context', 'unknown')})."
        ),
        "ACCOUNT_ACCESS_FAILED": "Account access attempt failed.",
        "TRANSACTION_ACCESS_FAILED": "Transaction access attempt failed.",
        "TOKEN_HIJACKING_DETECTED": f"Same token fingerprint observed from context '{details.get('context_observed')}'.",
        "CONSENT_PERMISSION_DENIED": f"Access denied — no authorized consent for '{details.get('required_permission')}'.",
        "CONSENT_BASED_FRAUD_DETECTED": (
            f"Application attempted '{details.get('required_permission')}' access "
            f"outside its authorized consent."
        ),
        "CROSS_BORDER_EXFILTRATION_DETECTED": (
            f"Financial data access associated with simulated destination country "
            f"'{details.get('destination_country')}'."
        ),
        "CONSENT_CREATED": "Consent created.",
        "CONSENT_AUTHORIZED": "Consent authorized.",
        "CONSENT_REJECTED": "Consent rejected.",
        "FINDING_STATUS_CHANGED": (
            f"Finding status changed from '{details.get('old_status')}' to "
            f"'{details.get('new_status')}' by {details.get('actor', 'unknown')}."
        ),
    }

    return descriptions.get(
        event_type, event_type.replace("_", " ").title() or "Forensic event recorded."
    )


def _describe_custody_event(custody: dict) -> str:
    action = custody.get("action", "")
    actor = custody.get("actor", "unknown")

    if action == "CREATED":
        return f"Evidence preserved by {actor}."
    if action == "ACCESSED":
        return f"Evidence accessed by {actor}."
    if action == "ANALYSED":
        return f"Evidence analysed by {actor}."
    if action == "VERIFIED":
        return f"Evidence verified by {actor}."
    if action == "EXPORTED":
        return f"Evidence exported by {actor}."
    if action == "TRANSFERRED":
        return f"Evidence transferred by {actor}."
    return f"Custody action '{action}' recorded by {actor}."


def get_related_event_ids(finding: dict) -> list[str]:
    try:
        return json.loads(finding.get("related_event_ids_json") or "[]")
    except (TypeError, ValueError):
        return []

# for a given finding, returns a list of all forensic events and custody events related to that finding, in chronological order
#customer id is resolved from the finding itself, or from the account_id and application_id if not directly present

def _resolve_customer_id(finding: dict) -> str | None:
    
    if finding.get("customer_id"):
        return finding["customer_id"]

    account_id = finding.get("account_id")
    application_id = finding.get("application_id")
    if not account_id or not application_id:
        return None

    consents = get_consents_for_account(account_id)
    matching = [c for c in consents if c["application_id"] == application_id]
    if not matching:
        return None

    authorized = [c for c in matching if c["status"] == "AUTHORIZED"]
    chosen = authorized[0] if authorized else matching[0]
    return chosen.get("customer_id")

#readable summary of incident 
def _build_incident_summary(finding: dict, related_events: list[dict]) -> str:
   
    scenario_type = finding.get("scenario_type")
    app_name = None
    application = None
    if finding.get("application_id"):
        application = get_application_by_id(finding["application_id"])
        app_name = application["application_name"] if application else None
    app_label = app_name or "The application"

    account_id = finding.get("account_id")
    account_label = (
        f"account ••••{account_id[-5:]}"
        if account_id and len(account_id) >= 5
        else (f"account {account_id}" if account_id else "an account")
    )

    events_by_type = {}
    for event in related_events:
        events_by_type.setdefault(event["event_type"], []).append(event)

    if scenario_type == "CREDENTIAL_THEFT":
        detected = events_by_type.get("CREDENTIAL_THEFT_DETECTED", [])
        if detected:
            d = _safe_details(detected[0])
            baseline = d.get("baseline_context", "an established context")
            suspicious = d.get("suspicious_context", "an unrecognized context")
            return (
                f"{app_label}'s valid credentials were used to obtain a new access token "
                f"from client context '{suspicious}', which differs from its established "
                f"context '{baseline}', for {account_label}."
            )
        return f"{app_label}'s credentials were used from an unexpected context, affecting {account_label}."

    if scenario_type == "TOKEN_HIJACKING":
        detected = events_by_type.get("TOKEN_HIJACKING_DETECTED", [])
        issued = events_by_type.get("TOKEN_ISSUED", [])
        original_context = (
            _safe_details(issued[0]).get("client_context") if issued else None
        )
        replay_context = (
            _safe_details(detected[0]).get("context_observed") if detected else None
        )

        parts = [
            f"The same {app_label} access token was observed accessing {account_label} from two different application contexts."
        ]
        if original_context:
            parts.append(f"The token was first used from {original_context}")
            if replay_context:
                parts.append(
                    f"and was subsequently replayed from {replay_context}, triggering Token Hijacking detection."
                )
            else:
                parts.append(
                    "and was subsequently replayed from a different context, triggering Token Hijacking detection."
                )
        return " ".join(parts)

    if scenario_type == "CONSENT_BASED_FRAUD":
        detected = events_by_type.get("CONSENT_BASED_FRAUD_DETECTED", [])
        permission = (
            _safe_details(detected[0]).get("required_permission") if detected else None
        )
        permission_label = {
            "accounts": "Account Information",
            "transactions": "Transaction History",
        }.get(permission, permission or "data outside its authorization")
        return (
            f"{app_label} attempted to access {permission_label} for {account_label} "
            f"beyond what the customer had authorized. The request was denied and classified "
            f"as Consent-Based Fraud."
        )

    if scenario_type == "CROSS_BORDER_DATA_EXFILTRATION":
        detected = events_by_type.get("CROSS_BORDER_EXFILTRATION_DETECTED", [])
        destination = (
            _safe_details(detected[0]).get("destination_country") if detected else None
        )
        destination_label = (
            f"'{destination}'" if destination else "a foreign jurisdiction"
        )
        return (
            f"A successful, authorized {app_label} access to {account_label} was associated "
            f"with simulated destination country {destination_label}, outside the expected "
            f"'ZA' jurisdiction, triggering Cross-Border Data Exfiltration detection."
        )

    return finding.get("description", "")


def get_investigation_summary(finding_id: str) -> dict | None:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return None

    related_event_ids = get_related_event_ids(finding)
    related_events = [get_forensic_event_by_id(eid) for eid in related_event_ids]
    related_events = [e for e in related_events if e is not None]

    application = None
    if finding.get("application_id"):
        application = get_application_by_id(finding["application_id"])

    consent = None
    if finding.get("consent_id"):
        consent = get_consent(finding["consent_id"])

    resolved_customer_id = _resolve_customer_id(finding)

    evidence_integrity = verify_evidence_chain()
    custody_integrity = verify_custody_chain()

    return {
        "finding_id": finding["finding_id"],
        "scenario_type": finding["scenario_type"],
        "severity": finding["severity"],
        "status": finding["status"],
        "title": finding["title"],
        "description": finding["description"],
        "incident_summary": _build_incident_summary(finding, related_events),
        "detected_at": finding["detected_at"],
        "application": (
            {
                "application_id": application["application_id"],
                "application_name": application["application_name"],
            }
            if application
            else None
        ),
        "customer_id": resolved_customer_id,
        "account_id": finding.get("account_id"),
        "consent": (
            {
                "consent_id": consent["consent_id"],
                "status": consent["status"],
                "permissions": json.loads(consent["permissions_json"]),
            }
            if consent
            else None
        ),
        "token_fingerprint": finding.get("token_fingerprint"),
        "evidence_count": len(related_event_ids),
        "evidence_integrity": "VALID" if evidence_integrity["valid"] else "INVALID",
        "custody_integrity": "VALID" if custody_integrity["valid"] else "INVALID",
    }


def get_related_evidence(finding_id: str) -> list[dict] | None:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return None

    related_event_ids = get_related_event_ids(finding)
    evidence_items = []

    for event_id in related_event_ids:
        event = get_forensic_event_by_id(event_id)

        if event is None:
            evidence_items.append({"event_id": event_id, "status": "MISSING"})
            continue

        custody_history = get_custody_events(evidence_id=event_id)

        interaction = (
            get_api_interaction_by_id(event["interaction_id"])
            if event.get("interaction_id")
            else None
        )

        evidence_items.append(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "timestamp": event["timestamp"],
                "account_id": event.get("account_id"),
                "details": _safe_details(event),
                "event_hash": event.get("event_hash"),
                "previous_hash": event.get("previous_hash"),
                "integrity_status": check_single_event_integrity(event_id),
                "custody_event_count": len(custody_history),
                "source": interaction.get("source") if interaction else None,
                "destination": interaction.get("destination") if interaction else None,
            }
        )

    return evidence_items


def get_custody_history_for_finding(finding_id: str) -> dict | None:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return None

    related_event_ids = get_related_event_ids(finding)
    history = {}

    for event_id in related_event_ids:
        custody_events = get_custody_events(evidence_id=event_id)
        history[event_id] = [
            {
                "timestamp": c["timestamp"],
                "actor": c["actor"],
                "action": c["action"],
                "from_holder": c.get("from_holder"),
                "to_holder": c.get("to_holder"),
                "reason": c.get("reason"),
                "integrity_status": c.get("integrity_status"),
                "evidence_hash": c.get("evidence_hash"),
            }
            for c in custody_events
        ]

    return history


def build_timeline(finding_id: str) -> list[dict] | None:
    finding = get_finding_by_id(finding_id)
    if finding is None:
        return None

    related_event_ids = get_related_event_ids(finding)
    timeline_items = []

    for event_id in related_event_ids:
        event = get_forensic_event_by_id(event_id)
        if event is None:
            continue

        interaction = (
            get_api_interaction_by_id(event["interaction_id"])
            if event.get("interaction_id")
            else None
        )

        timeline_items.append(
            {
                "timestamp": event["timestamp"],
                "category": "FORENSIC_EVENT",
                "event_type": event["event_type"],
                "description": _describe_forensic_event(event),
                "event_id": event["event_id"],
                "interaction_id": event.get("interaction_id"),
                "source": interaction.get("source") if interaction else None,
                "destination": interaction.get("destination") if interaction else None,
            }
        )

        if interaction:
            timeline_items.append(
                {
                    "timestamp": interaction["timestamp"],
                    "category": "API_INTERACTION",
                    "event_type": "API_REQUEST",
                    "description": f"{interaction['http_method']} {interaction['endpoint']}",
                    "event_id": None,
                    "interaction_id": interaction["interaction_id"],
                    "response_status": interaction.get("response_status"),
                    "source": interaction.get("source"),
                    "destination": interaction.get("destination"),
                }
            )

        for custody in get_custody_events(evidence_id=event_id):
            timeline_items.append(
                {
                    "timestamp": custody["timestamp"],
                    "category": "CUSTODY",
                    "event_type": custody["action"],
                    "description": _describe_custody_event(custody),
                    "event_id": custody["evidence_id"],
                    "interaction_id": None,
                }
            )

    timeline_items.append(
        {
            "timestamp": finding["detected_at"],
            "category": "FINDING",
            "event_type": "FINDING_CREATED",
            "description": f"Finding created: {finding['title']}",
            "event_id": None,
            "interaction_id": None,
        }
    )

    timeline_items.sort(key=lambda item: item["timestamp"])

    return timeline_items

#account related investigation summary including all forensic events etc
def get_account_investigation(account_id: str) -> dict:
   
    all_events = get_forensic_events()
    account_events = [e for e in all_events if e.get("account_id") == account_id]
    account_events.sort(key=lambda e: e["timestamp"])

    all_interactions = get_api_interactions()
    account_interactions = [
        i for i in all_interactions if i.get("account_id") == account_id
    ]
    account_interactions.sort(key=lambda i: i["timestamp"])

    all_findings = get_findings()
    account_findings = [f for f in all_findings if f.get("account_id") == account_id]

    consents = get_consents_for_account(account_id)
    application_ids_seen = set()
    consent_list = []
    for c in consents:
        application_ids_seen.add(c["application_id"])
        consent_list.append(
            {
                "consent_id": c["consent_id"],
                "application_id": c["application_id"],
                "permissions": json.loads(c["permissions_json"]),
                "status": c["status"],
                "created_at": c["created_at"],
                "authorized_at": c.get("authorized_at"),
            }
        )

    for f in account_findings:
        if f.get("application_id"):
            application_ids_seen.add(f["application_id"])
    for e in account_events:
        details = _safe_details(e)
        if details.get("application_id"):
            application_ids_seen.add(details["application_id"])

    applications = []
    for app_id in application_ids_seen:
        app = get_application_by_id(app_id)
        if app:
            applications.append(
                {
                    "application_id": app["application_id"],
                    "application_name": app["application_name"],
                    "status": app["status"],
                }
            )

    for c in consent_list:
        matching_app = next(
            (a for a in applications if a["application_id"] == c["application_id"]),
            None,
        )
        c["application_name"] = (
            matching_app["application_name"] if matching_app else "Unknown Application"
        )

    evidence_items = []
    for event in account_events:
        custody_history = get_custody_events(evidence_id=event["event_id"])
        evidence_items.append(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "timestamp": event["timestamp"],
                "details": _safe_details(event),
                "event_hash": event.get("event_hash"),
                "previous_hash": event.get("previous_hash"),
                "integrity_status": check_single_event_integrity(event["event_id"]),
                "custody_event_count": len(custody_history),
            }
        )

    custody_by_event = {
        event["event_id"]: [
            {
                "timestamp": c["timestamp"],
                "actor": c["actor"],
                "action": c["action"],
                "from_holder": c.get("from_holder"),
                "to_holder": c.get("to_holder"),
                "reason": c.get("reason"),
                "integrity_status": c.get("integrity_status"),
                "evidence_hash": c.get("evidence_hash"),
            }
            for c in get_custody_events(evidence_id=event["event_id"])
        ]
        for event in account_events
    }

    timeline_items = []
    for event in account_events:
        timeline_items.append(
            {
                "timestamp": event["timestamp"],
                "category": "FORENSIC_EVENT",
                "event_type": event["event_type"],
                "description": _describe_forensic_event(event),
                "event_id": event["event_id"],
                "interaction_id": event.get("interaction_id"),
            }
        )
    for interaction in account_interactions:
        timeline_items.append(
            {
                "timestamp": interaction["timestamp"],
                "category": "API_INTERACTION",
                "event_type": "API_REQUEST",
                "description": f"{interaction['http_method']} {interaction['endpoint']}",
                "event_id": None,
                "interaction_id": interaction["interaction_id"],
                "response_status": interaction.get("response_status"),
            }
        )
    timeline_items.sort(key=lambda item: item["timestamp"])

    evidence_integrity = verify_evidence_chain()
    custody_integrity = verify_custody_chain()

    findings_summary = [
        {
            "finding_id": f["finding_id"],
            "scenario_type": f["scenario_type"],
            "severity": f["severity"],
            "status": f["status"],
            "detected_at": f["detected_at"],
            "application_id": f.get("application_id"),
        }
        for f in account_findings
    ]

    return {
        "account_id": account_id,
        "overview": {
            "connected_application_count": len(applications),
            "active_consent_count": sum(
                1 for c in consent_list if c["status"] == "AUTHORIZED"
            ),
            "total_findings": len(account_findings),
            "total_api_interactions": len(account_interactions),
            "total_evidence_items": len(evidence_items),
        },
        "timeline": timeline_items,
        "consents": consent_list,
        "applications": applications,
        "api_communication": account_interactions,
        "findings": findings_summary,
        "evidence": evidence_items,
        "custody": custody_by_event,
        "evidence_integrity": "VALID" if evidence_integrity["valid"] else "INVALID",
        "custody_integrity": "VALID" if custody_integrity["valid"] else "INVALID",
    }