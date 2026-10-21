import json
import uuid
from datetime import datetime, timezone

from database.database import get_connection
from forensic.integrity import calculate_event_hash, get_latest_event_hash
from forensic.custody import record_custody_event


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_api_interaction(
    http_method: str,
    endpoint: str,
    response_status: int,
    account_id: str | None = None,
    source: str = "LOCAL_CLIENT",
    destination: str = "INVESTEC_SANDBOX",
) -> str:
    #records an API interaction in the forensic database and returns a unique interaction_id for linking to forensic events
    interaction_id = str(uuid.uuid4())
    timestamp = _utc_now_iso()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO api_interactions (
            interaction_id, timestamp, http_method, endpoint,
            account_id, response_status, source, destination
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            interaction_id,
            timestamp,
            http_method,
            endpoint,
            account_id,
            response_status,
            source,
            destination,
        ),
    )
    conn.commit()
    conn.close()

    return interaction_id


def record_forensic_event(
    interaction_id: str,
    event_type: str,
    actor_type: str = "third_party_application",
    actor_id: str = "obfir_client",
    account_id: str | None = None,
    details: dict | None = None,
) -> str:
   #records a forensic event in the forensic database and returns a unique event_id for linking to findings and custody events
    event_id = str(uuid.uuid4())
    timestamp = _utc_now_iso()
    details_json = json.dumps(details or {})
    created_at = timestamp

    event_data = {
        "event_id": event_id,
        "interaction_id": interaction_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "account_id": account_id,
        "details_json": details_json,
        "created_at": created_at,
    }

    previous_hash = get_latest_event_hash()
    event_hash = calculate_event_hash(event_data, previous_hash)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO forensic_events (
            event_id, interaction_id, timestamp, event_type,
            actor_type, actor_id, account_id, details_json, created_at,
            previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            interaction_id,
            timestamp,
            event_type,
            actor_type,
            actor_id,
            account_id,
            details_json,
            created_at,
            previous_hash,
            event_hash,
        ),
    )
    conn.commit()
    conn.close()

    # Custody creation happens AFTER the forensic event is safely
    # committed and never modifies event_hash/previous_hash.
    record_custody_event(
        evidence_id=event_id,
        actor="OBFIR_SYSTEM",
        action="CREATED",
        evidence_hash=event_hash,
        from_holder=None,
        to_holder="OBFIR_EVIDENCE_STORE",
        reason="Initial evidence preservation",
        integrity_status="VALID",
        timestamp=created_at,
    )

    return event_id


def find_events_by_token_fingerprint(
    token_fingerprint: str, event_types: list[str] | None = None
) -> list[str]:
    # Returns event_ids for forensic events matching the given token_fingerprint
    # and optionally filtered by event_types, in original insertion order.
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT event_id, event_type, details_json FROM forensic_events ORDER BY rowid ASC"
    )
    rows = cursor.fetchall()
    conn.close()

    matches = []
    for event_id, event_type, details_json in rows:
        if event_types and event_type not in event_types:
            continue
        try:
            details = json.loads(details_json) if details_json else {}
        except (TypeError, ValueError):
            continue
        if details.get("token_fingerprint") == token_fingerprint:
            matches.append(event_id)
    return matches

# returns a list of unique client contexts associated with a given token fingerprint, in original insertion order
def find_consent_event_ids(consent_id: str) -> list[str]:
   
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT event_id, event_type, details_json FROM forensic_events "
        "WHERE event_type IN ('CONSENT_CREATED', 'CONSENT_AUTHORIZED') ORDER BY rowid ASC"
    )
    rows = cursor.fetchall()
    conn.close()

    matches = []
    for event_id, event_type, details_json in rows:
        try:
            details = json.loads(details_json) if details_json else {}
        except (TypeError, ValueError):
            continue
        if details.get("consent_id") == consent_id:
            matches.append(event_id)
    return matches
