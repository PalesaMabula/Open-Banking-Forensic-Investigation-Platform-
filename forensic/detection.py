import json
import sqlite3
import uuid
from datetime import datetime, timezone

from database.database import get_connection
from forensic.evidence import record_forensic_event

SEVERITY_BY_SCENARIO = {
    "CREDENTIAL_THEFT": "HIGH",
    "TOKEN_HIJACKING": "CRITICAL",
    "CONSENT_BASED_FRAUD": "HIGH",
    "CROSS_BORDER_DATA_EXFILTRATION": "CRITICAL",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_finding(
    scenario_type: str,
    title: str,
    description: str,
    related_event_ids: list[str],
    application_id: str | None = None,
    customer_id: str | None = None,
    account_id: str | None = None,
    consent_id: str | None = None,
    token_fingerprint: str | None = None,
) -> dict:
   #store the finding in the forensic_findings table with a unique finding_id and a timestamp
    finding_id = str(uuid.uuid4())
    detected_at = _utc_now_iso()
    severity = SEVERITY_BY_SCENARIO.get(scenario_type, "MEDIUM")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO forensic_findings (
            finding_id, scenario_type, detected_at, severity, title,
            description, application_id, customer_id, account_id,
            consent_id, token_fingerprint, related_event_ids_json,
            status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding_id,
            scenario_type,
            detected_at,
            severity,
            title,
            description,
            application_id,
            customer_id,
            account_id,
            consent_id,
            token_fingerprint,
            json.dumps(related_event_ids),
            "OPEN",
            detected_at,
        ),
    )
    conn.commit()
    conn.close()

    return get_finding_by_id(finding_id)


def get_findings() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_findings ORDER BY detected_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_finding_by_id(finding_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM forensic_findings WHERE finding_id = ?", (finding_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def detect_credential_theft(
    application_id: str,
    client_id: str,
    baseline_context: str,
    new_context: str,
    related_event_ids: list[str],
    account_id: str | None = None,
) -> dict:
    detection_event_id = record_forensic_event(
        interaction_id=None,
        event_type="CREDENTIAL_THEFT_DETECTED",
        account_id=account_id,
        details={
            "application_id": application_id,
            "client_id": client_id,
            "baseline_context": baseline_context,
            "suspicious_context": new_context,
        },
    )
    return create_finding(
        scenario_type="CREDENTIAL_THEFT",
        title="Valid credentials used from unexpected client context",
        description=(
            f"Application '{application_id}' authenticated successfully and was "
            f"issued a new token from client context '{new_context}', which "
            f"differs from its established baseline context '{baseline_context}'."
        ),
        related_event_ids=related_event_ids + [detection_event_id],
        application_id=application_id,
        account_id=account_id,
    )

#check if the same token is used  form diferrent client 
def check_token_context_consistency(token_fingerprint: str) -> list[str]:
   
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT details_json FROM forensic_events
        WHERE event_type IN ('ACCOUNT_DATA_ACCESSED', 'TRANSACTION_DATA_ACCESSED')
        ORDER BY rowid ASC
        """)
    rows = cursor.fetchall()
    conn.close()

    contexts = []
    for (details_json,) in rows:
        try:
            details = json.loads(details_json) if details_json else {}
        except (TypeError, ValueError):
            continue
        if details.get("token_fingerprint") == token_fingerprint:
            context = details.get("client_context")
            if context and context not in contexts:
                contexts.append(context)
    return contexts


def detect_token_hijacking(
    token_fingerprint: str,
    application_id: str,
    new_context: str,
    related_event_ids: list[str],
    account_id: str | None = None,
) -> dict:
    detection_event_id = record_forensic_event(
        interaction_id=None,
        event_type="TOKEN_HIJACKING_DETECTED",
        account_id=account_id,
        details={
            "application_id": application_id,
            "token_fingerprint": token_fingerprint,
            "context_observed": new_context,
        },
    )
    return create_finding(
        scenario_type="TOKEN_HIJACKING",
        title="Same bearer token used from multiple client contexts",
        description=(
            f"Token fingerprint '{token_fingerprint}' was used successfully from "
            f"more than one simulated client context, consistent with token replay."
        ),
        related_event_ids=related_event_ids + [detection_event_id],
        application_id=application_id,
        token_fingerprint=token_fingerprint,
        account_id=account_id,
    )


def detect_consent_fraud(
    application_id: str,
    customer_id: str | None,
    account_id: str | None,
    consent_id: str | None,
    required_permission: str,
    related_event_ids: list[str],
) -> dict:
    """
    Classifies ONE deliberately-provoked consent denial as Consent-
    Based Fraud. Only ever called by the controlled scenario runner —
    ordinary 403s from real usage are never auto-classified this way.
    """
    detection_event_id = record_forensic_event(
        interaction_id=None,
        event_type="CONSENT_BASED_FRAUD_DETECTED",
        account_id=account_id,
        details={
            "application_id": application_id,
            "customer_id": customer_id,
            "account_id": account_id,
            "consent_id": consent_id,
            "required_permission": required_permission,
        },
    )
    return create_finding(
        scenario_type="CONSENT_BASED_FRAUD",
        title="Access attempted outside authorized consent",
        description=(
            f"Application '{application_id}' attempted to access "
            f"'{required_permission}' data outside the permissions granted "
            f"by its authorized consent."
        ),
        related_event_ids=related_event_ids + [detection_event_id],
        application_id=application_id,
        customer_id=customer_id,
        account_id=account_id,
        consent_id=consent_id,
    )


def detect_cross_border_exfiltration(
    application_id: str,
    account_id: str | None,
    destination_country: str,
    related_event_ids: list[str],
) -> dict:
    """
    Rule: a successful financial-data access was associated with
    simulated destination-country metadata outside "ZA". Normal
    traffic always defaults to "ZA" — only the cross-border scenario
    runner ever sets a different value, so this cannot overdetect
    against real traffic in this prototype.
    """
    detection_event_id = record_forensic_event(
        interaction_id=None,
        event_type="CROSS_BORDER_EXFILTRATION_DETECTED",
        account_id=account_id,
        details={
            "application_id": application_id,
            "account_id": account_id,
            "destination_country": destination_country,
        },
    )
    return create_finding(
        scenario_type="CROSS_BORDER_DATA_EXFILTRATION",
        title="Sensitive financial data associated with foreign destination",
        description=(
            f"Access to account data was associated with simulated "
            f"destination country '{destination_country}', outside the "
            f"expected 'ZA' jurisdiction."
        ),
        related_event_ids=related_event_ids + [detection_event_id],
        application_id=application_id,
        account_id=account_id,
    )

#updates finds and returns new updates 
def update_finding_status(finding_id: str, new_status: str) -> dict | None:
   
    existing = get_finding_by_id(finding_id)
    if existing is None:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE forensic_findings SET status = ? WHERE finding_id = ?",
        (new_status, finding_id),
    )
    conn.commit()
    conn.close()

    return get_finding_by_id(finding_id)
