import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone

from database.database import get_connection
from forensic.integrity import (
    canonical_json,
    calculate_event_hash,
    GENESIS_PREVIOUS_HASH,
)

# Same genesis convention as the Step 5 evidence chain, for consistency.
GENESIS_CUSTODY_HASH = ""

ALLOWED_ACTIONS = {
    "CREATED",
    "ACCESSED",
    "ANALYSED",
    "VERIFIED",
    "EXPORTED",
    "TRANSFERRED",
}

CUSTODY_HASH_FIELDS = [
    "custody_event_id",
    "evidence_id",
    "timestamp",
    "actor",
    "action",
    "from_holder",
    "to_holder",
    "reason",
    "integrity_status",
    "evidence_hash",
    "previous_custody_hash",
    "created_at",
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calculate_custody_hash(custody_data: dict) -> str:
    hash_input = {field: custody_data.get(field) for field in CUSTODY_HASH_FIELDS}
    serialized = canonical_json(hash_input)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

#calculates the hash of a single forensic event and compares it to the stored hash to determine if the event has been tampered with

def check_single_event_integrity(event_id: str) -> str:
   
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_events WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return "UNKNOWN"

    event = dict(row)
    previous_hash = event.get("previous_hash") or GENESIS_PREVIOUS_HASH
    recalculated = calculate_event_hash(event, previous_hash)
# Returns "VALID" if the hashes match, "INVALID" if they don't, and "UNKNOWN" if the event_id is not found in the database
    return "VALID" if recalculated == event.get("event_hash") else "INVALID"


def _get_latest_custody_hash(cursor) -> str:
    cursor.execute(
        "SELECT custody_hash FROM custody_events ORDER BY rowid DESC LIMIT 1"
    )
    row = cursor.fetchone()
    if row is None or row[0] is None:
        return GENESIS_CUSTODY_HASH
    return row[0]

#chain of cutsody events is verified by recomputing the custody hash for each event 
def record_custody_event(
    evidence_id: str,
    actor: str,
    action: str,
    evidence_hash: str | None,
    from_holder: str | None = None,
    to_holder: str | None = None,
    reason: str | None = None,
    integrity_status: str = "UNKNOWN",
    timestamp: str | None = None,
) -> dict:
   
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported custody action: {action}")

    custody_event_id = str(uuid.uuid4())
    event_timestamp = timestamp or _utc_now_iso()
    created_at = _utc_now_iso()

    conn = get_connection()
    cursor = conn.cursor()
#check if hahs of the previous custody event is stored in the database
    previous_custody_hash = _get_latest_custody_hash(cursor)

    custody_data = {
        "custody_event_id": custody_event_id,
        "evidence_id": evidence_id,
        "timestamp": event_timestamp,
        "actor": actor,
        "action": action,
        "from_holder": from_holder,
        "to_holder": to_holder,
        "reason": reason,
        "integrity_status": integrity_status,
        "evidence_hash": evidence_hash,
        "previous_custody_hash": previous_custody_hash,
        "created_at": created_at,
    }
    custody_hash = _calculate_custody_hash(custody_data)

    cursor.execute(
        """
        INSERT INTO custody_events (
            custody_event_id, evidence_id, timestamp, actor, action,
            from_holder, to_holder, reason, integrity_status,
            evidence_hash, previous_custody_hash, custody_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            custody_event_id,
            evidence_id,
            event_timestamp,
            actor,
            action,
            from_holder,
            to_holder,
            reason,
            integrity_status,
            evidence_hash,
            previous_custody_hash,
            custody_hash,
            created_at,
        ),
    )
    conn.commit()
    conn.close()

    custody_data["custody_hash"] = custody_hash
    return custody_data

# get all custody events for a specific evidence_id or all custody events if no evdince if is there 
def get_custody_events(evidence_id: str | None = None) -> list[dict]:
  
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if evidence_id:
        cursor.execute(
            "SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY rowid ASC",
            (evidence_id,),
        )
    else:
        cursor.execute("SELECT * FROM custody_events ORDER BY rowid ASC")

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def verify_custody_chain() -> dict:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM custody_events ORDER BY rowid ASC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    expected_previous_hash = GENESIS_CUSTODY_HASH

    for index, row in enumerate(rows, start=1):
        if row.get("previous_custody_hash") != expected_previous_hash:
            return {
                "valid": False,
                "custody_events_checked": index - 1,
                "broken_custody_event_id": row["custody_event_id"],
                "reason": "previous_custody_hash linkage mismatch",
            }

        recalculated = _calculate_custody_hash(row)

        if recalculated != row.get("custody_hash"):
            return {
                "valid": False,
                "custody_events_checked": index - 1,
                "broken_custody_event_id": row["custody_event_id"],
                "reason": "custody hash mismatch",
            }

        expected_previous_hash = recalculated

    return {
        "valid": True,
        "custody_events_checked": len(rows),
        "broken_custody_event_id": None,
        "reason": None,
    }

#checks of forenics event has been recorded in the custody events table and if not, it records a new custody event for that forensic even
def backfill_created_custody_events() -> int:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM forensic_events ORDER BY rowid ASC")
    forensic_events = [dict(row) for row in cursor.fetchall()]

    cursor.execute(
        "SELECT DISTINCT evidence_id FROM custody_events WHERE action = 'CREATED'"
    )
    already_has_created = {row[0] for row in cursor.fetchall()}
    conn.close()

    backfilled_count = 0
    for event in forensic_events:
        if event["event_id"] in already_has_created:
            continue

        record_custody_event(
            evidence_id=event["event_id"],
            actor="OBFIR_SYSTEM",
            action="CREATED",
            evidence_hash=event.get("event_hash"),
            from_holder=None,
            to_holder="OBFIR_EVIDENCE_STORE",
            reason="Initial evidence preservation",
            integrity_status="VALID",
            timestamp=event["created_at"],
        )
        backfilled_count += 1

    return backfilled_count
