import hashlib
import json
import sqlite3

from database.database import get_connection

# The first event in the chain has no event before it...  
# use an emoty string  so it hashes and compares as ordinary text with no
# special meaning
GENESIS_PREVIOUS_HASH = ""

# The exact set and order of evidence fields used to build the hash input.
# Verification MUST use this same field set or recomputed hashes will
# never match stored ones.
HASH_FIELDS = [
    "event_id",
    "interaction_id",
    "timestamp",
    "event_type",
    "actor_type",
    "actor_id",
    "account_id",
    "details_json",
    "created_at",
]

# The first custody event in the chain has no custody event before it...  use an empty
def canonical_json(data: dict) -> str:
   
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

#calculates the hash of a single forensic event and compares it to the stored hash to determine if the event has been tampered with
def calculate_event_hash(event_data: dict, previous_hash: str) -> str:
   
    hash_input = {field: event_data.get(field) for field in HASH_FIELDS}
    hash_input["previous_hash"] = previous_hash

    serialized = canonical_json(hash_input)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def get_latest_event_hash() -> str:
    """
    Returns the event_hash of the most recently inserted forensic event
    (by insertion order), or the genesis value if no events exist yet.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT event_hash FROM forensic_events ORDER BY rowid DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if row is None or row[0] is None:
        return GENESIS_PREVIOUS_HASH
    return row[0]

#previous hash is used to link the current event to the previous event in the chain, ensuring that any tampering with past events will break the chain and be detectable
def backfill_hash_chain() -> int:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM forensic_events WHERE event_hash IS NULL ORDER BY rowid ASC"
    )
    rows_to_backfill = [dict(row) for row in cursor.fetchall()]

    if not rows_to_backfill:
        conn.close()
        return 0

    previous_hash = get_latest_event_hash()

    for row in rows_to_backfill:
        event_hash = calculate_event_hash(row, previous_hash)
        cursor.execute(
            "UPDATE forensic_events SET previous_hash = ?, event_hash = ? WHERE event_id = ?",
            (previous_hash, event_hash, row["event_id"]),
        )
        previous_hash = event_hash

    conn.commit()
    conn.close()
    return len(rows_to_backfill)

# records a custody event in the forensic database and returns a unique custody_event_id for linking to evidence and findings
def verify_evidence_chain() -> dict:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_events ORDER BY rowid ASC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    expected_previous_hash = GENESIS_PREVIOUS_HASH

    for index, row in enumerate(rows, start=1):
        if row.get("previous_hash") != expected_previous_hash:
            return {
                "valid": False,
                "events_checked": index - 1,
                "failed_event_id": row["event_id"],
                "reason": "previous_hash linkage mismatch",
            }

        recalculated_hash = calculate_event_hash(row, expected_previous_hash)

        if recalculated_hash != row.get("event_hash"):
            return {
                "valid": False,
                "events_checked": index - 1,
                "failed_event_id": row["event_id"],
                "reason": "event hash mismatch",
            }

        expected_previous_hash = recalculated_hash

    return {
        "valid": True,
        "events_checked": len(rows),
    }
