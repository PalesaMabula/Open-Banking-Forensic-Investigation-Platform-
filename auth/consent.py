import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from database.database import get_connection, get_all_applications
#hw long this consent is valid for 
CONSENT_LIFETIME_DAYS = 90

#this shows diffrent consents for the tpps 
DEMO_CONSENT_BASELINE = {
    "BudgetWise": ["accounts", "transactions"],
    "InsureWise": ["accounts"],
}

DEMO_CUSTOMER_ID = "customer-001"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def create_consent(
    application_id: str,
    customer_id: str,
    permissions: list[str],
    account_id: str | None = None,
) -> dict:
    consent_id = str(uuid.uuid4())
    created_at = _utc_now_iso()
    permissions_json = json.dumps(permissions)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO consents (
            consent_id, application_id, customer_id, account_id,
            permissions_json, status, created_at, authorized_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            consent_id,
            application_id,
            customer_id,
            account_id,
            permissions_json,
            "PENDING",
            created_at,
            None,
            None,
        ),
    )
    conn.commit()
    conn.close()

    return get_consent(consent_id)


def get_consent(consent_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM consents WHERE consent_id = ?", (consent_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def authorize_consent(consent_id: str) -> dict | None:
    consent = get_consent(consent_id)
    if consent is None:
        return None

    authorized_at = _utc_now()
    expires_at = authorized_at + timedelta(days=CONSENT_LIFETIME_DAYS)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE consents SET status = 'AUTHORIZED', authorized_at = ?, expires_at = ? WHERE consent_id = ?",
        (authorized_at.isoformat(), expires_at.isoformat(), consent_id),
    )
    conn.commit()
    conn.close()

    return get_consent(consent_id)


def reject_consent(consent_id: str) -> dict | None:
    """
    Customer-controlled rejection of a pending consent request. Sets
    status to REJECTED. Returns None if the consent does not exist.
    Does not touch AUTHORIZED consents — rejection is only meaningful
    for a request the customer hasn't yet approved, but no state
    check is enforced here beyond existence, so re-rejecting an
    already-rejected or authorized consent is a harmless no-op state
    change rather than an error.
    """
    consent = get_consent(consent_id)
    if consent is None:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE consents SET status = 'REJECTED' WHERE consent_id = ?",
        (consent_id,),
    )
    conn.commit()
    conn.close()

    return get_consent(consent_id)

# Find an authorized consent for a specific application and permission
def find_authorized_consent(
    application_id: str,
    permission: str,
    account_id: str | None = None,
) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM consents WHERE application_id = ? AND status = 'AUTHORIZED'",
        (application_id,),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    now = _utc_now()

    for consent in rows:
        permissions = json.loads(consent["permissions_json"])
        if permission not in permissions:
            continue
        if consent["account_id"] and account_id and consent["account_id"] != account_id:
            continue
        if consent["expires_at"]:
            expires_at = datetime.fromisoformat(consent["expires_at"])
            if now > expires_at:
                continue
        return consent

    return None

# Get all consents for a specific account, ordered by creation date descending
def get_consents_for_account(account_id: str) -> list[dict]:
   
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM consents WHERE account_id = ? ORDER BY created_at DESC",
        (account_id,),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

# Seed demo consents for the demo applications
def seed_demo_consents() -> None:
   
    from forensic.evidence import record_api_interaction, record_forensic_event

    applications = get_all_applications()

    for app_row in applications:
        permissions = DEMO_CONSENT_BASELINE.get(app_row["application_name"])
        if permissions is None:
            continue

        existing = find_authorized_consent(app_row["application_id"], permissions[0])
        if existing is not None:
            continue

        consent = create_consent(
            application_id=app_row["application_id"],
            customer_id=DEMO_CUSTOMER_ID,
            permissions=permissions,
        )

        interaction_id = record_api_interaction(
            http_method="POST",
            endpoint="/consents",
            response_status=200,
            source="TPP",
            destination="OBFIR",
        )
        record_forensic_event(
            interaction_id=interaction_id,
            event_type="CONSENT_CREATED",
            details={
                "consent_id": consent["consent_id"],
                "application_id": consent["application_id"],
                "customer_id": consent["customer_id"],
                "account_id": consent["account_id"],
                "permissions": permissions,
                "status": consent["status"],
            },
        )

        authorized = authorize_consent(consent["consent_id"])

        interaction_id = record_api_interaction(
            http_method="POST",
            endpoint=f"/consents/{consent['consent_id']}/authorize",
            response_status=200,
            source="CUSTOMER",
            destination="OBFIR",
        )
        record_forensic_event(
            interaction_id=interaction_id,
            event_type="CONSENT_AUTHORIZED",
            details={
                "consent_id": authorized["consent_id"],
                "application_id": authorized["application_id"],
                "customer_id": authorized["customer_id"],
                "account_id": authorized["account_id"],
                "permissions": permissions,
                "status": authorized["status"],
            },
        )