import hashlib
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database.database import get_connection
from forensic.evidence import record_api_interaction, record_forensic_event
from forensic.detection import detect_credential_theft
import config

# how long the token is valid for in minutes 
TOKEN_LIFETIME_MINUTES = 30

bearer_scheme = HTTPBearer(auto_error=False)

DEMO_APPLICATIONS = [
    {
        "application_name": "BudgetWise",
        "client_id_env": "OBFIR_TPP_CLIENT_ID",
        "client_secret_env": "OBFIR_TPP_CLIENT_SECRET",
    },
    {
        "application_name": "InsureWise",
        "client_id_env": "OBFIR_APP2_CLIENT_ID",
        "client_secret_env": "OBFIR_APP2_CLIENT_SECRET",
    },
]


# persistent application session rather than re-authenticating on

_ACTIVE_APP_TOKENS: dict[str, str] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()

#SHA256 hash of a value, used for storing client secrets and access tokens securely
def hash_value(value: str) -> str:
    
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

# Seed demo applications into the database 
#bugetwise and insurewise are seeded into the database with their client_id and client_secret from the environment variables


def seed_demo_applications() -> None:
   
    conn = get_connection()
    cursor = conn.cursor()

    for app_def in DEMO_APPLICATIONS:
        client_id = getattr(config, app_def["client_id_env"])
        client_secret = getattr(config, app_def["client_secret_env"])

        if not client_id or not client_secret:
            conn.close()
            raise RuntimeError(
                f"{app_def['client_id_env']} and {app_def['client_secret_env']} must be "
                f"set in .env to seed '{app_def['application_name']}'."
            )

        cursor.execute(
            "SELECT application_id, application_name FROM applications WHERE client_id = ?",
            (client_id,),
        )
        existing = cursor.fetchone()

        if existing is not None:
            existing_name = existing[1]
            if existing_name != app_def["application_name"]:
                cursor.execute(
                    "UPDATE applications SET application_name = ? WHERE client_id = ?",
                    (app_def["application_name"], client_id),
                )
            continue

        application_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO applications (
                application_id, client_id, client_secret_hash,
                application_name, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                client_id,
                hash_value(client_secret),
                app_def["application_name"],
                _utc_now_iso(),
                "ACTIVE",
            ),
        )

    conn.commit()
    conn.close()


def authenticate_application(client_id: str, client_secret: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM applications WHERE client_id = ? AND status = 'ACTIVE'",
        (client_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    application = dict(row)
    if application["client_secret_hash"] != hash_value(client_secret):
        return None

    return application


def issue_access_token(application_id: str, client_context: str) -> dict:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_value(raw_token)
    token_id = str(uuid.uuid4())

    issued_at = _utc_now()
    expires_at = issued_at + timedelta(minutes=TOKEN_LIFETIME_MINUTES)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO access_tokens (
            token_id, application_id, token_hash,
            issued_at, expires_at, status, issued_context
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token_id,
            application_id,
            token_hash,
            issued_at.isoformat(),
            expires_at.isoformat(),
            "ACTIVE",
            client_context,
        ),
    )
    conn.commit()
    conn.close()

    return {
        "raw_token": raw_token,
        "token_hash": token_hash,
        "expires_in": TOKEN_LIFETIME_MINUTES * 60,
    }


def get_baseline_context(application_id: str) -> str | None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT issued_context FROM access_tokens WHERE application_id = ? ORDER BY rowid ASC LIMIT 1",
        (application_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return row[0] if row[0] is not None else "UNSPECIFIED-CONTEXT"

# Validate an access token by checking its hash against the database and ensuring it is active and not expired.
def validate_access_token(raw_token: str) -> dict | None:
    token_hash = hash_value(raw_token)

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM access_tokens WHERE token_hash = ? AND status = 'ACTIVE'",
        (token_hash,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    token = dict(row)
    expires_at = datetime.fromisoformat(token["expires_at"])
    if _utc_now() > expires_at:
        return None

    return token

# Get the current access token from the requests authorzation header validate it an return the token data.
def get_current_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = validate_access_token(credentials.credentials)
    if token is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return token


def authenticate_and_issue_token(
    client_id: str,
    client_secret: str,
    client_context: str,
    account_id: str | None = None,
) -> dict:
    endpoint = "/auth/token"
    application = authenticate_application(client_id, client_secret)

    if application is None:
        interaction_id = record_api_interaction(
            http_method="POST",
            endpoint=endpoint,
            response_status=401,
            source="LOCAL_CLIENT",
            destination="OBFIR",
        )
        record_forensic_event(
            interaction_id=interaction_id,
            event_type="AUTHENTICATION_FAILED",
            details={
                "client_id": client_id,
                "result": "invalid_credentials",
                "client_context": client_context,
            },
        )
        return {"success": False}

    application_id = application["application_id"]
    baseline_context = get_baseline_context(application_id)

    interaction_id = record_api_interaction(
        http_method="POST",
        endpoint=endpoint,
        response_status=200,
        source="LOCAL_CLIENT",
        destination="OBFIR",
    )
    record_forensic_event(
        interaction_id=interaction_id,
        event_type="AUTHENTICATION_SUCCEEDED",
        details={
            "application_id": application_id,
            "client_id": client_id,
            "client_context": client_context,
        },
    )

    token_data = issue_access_token(application_id, client_context)

    token_event_id = record_forensic_event(
        interaction_id=interaction_id,
        event_type="TOKEN_ISSUED",
        details={
            "application_id": application_id,
            "client_id": client_id,
            "client_context": client_context,
            "token_fingerprint": token_data["token_hash"],
        },
    )

    result = {
        "success": True,
        "raw_token": token_data["raw_token"],
        "expires_in": token_data["expires_in"],
        "application_id": application_id,
        "detected": False,
        "finding_id": None,
    }

    if baseline_context is not None and baseline_context != client_context:
        context_event_id = record_forensic_event(
            interaction_id=interaction_id,
            event_type="NEW_CLIENT_CONTEXT_OBSERVED",
            details={
                "application_id": application_id,
                "baseline_context": baseline_context,
                "new_context": client_context,
            },
        )
        finding = detect_credential_theft(
            application_id=application_id,
            client_id=client_id,
            baseline_context=baseline_context,
            new_context=client_context,
            related_event_ids=[token_event_id, context_event_id],
            account_id=account_id,
        )
        if finding:
            result["detected"] = True
            result["finding_id"] = finding["finding_id"]

    return result

# get client id and secret ofor the tpps 
def get_app_credentials(application_name: str) -> tuple[str, str] | None:
    """
    Returns (client_id, client_secret) for BudgetWise/InsureWise from
    server-side config — never exposed to the browser.
    """
    for app_def in DEMO_APPLICATIONS:
        if app_def["application_name"] == application_name:
            client_id = getattr(config, app_def["client_id_env"])
            client_secret = getattr(config, app_def["client_secret_env"])
            return client_id, client_secret
    return None


def default_context_for_app(application_name: str) -> str:
    return f"{application_name.upper()}-SERVER-01"


def get_active_app_token(application_name: str) -> str | None:
    """
    Returns the application's currently active raw bearer token if one
    exists and is still valid — models a persistent application
    session. Returns None (and clears the stale entry) if no session
    exists or the cached token has expired/been revoked.
    """
    raw_token = _ACTIVE_APP_TOKENS.get(application_name)
    if raw_token is None:
        return None
    if validate_access_token(raw_token) is None:
        _ACTIVE_APP_TOKENS.pop(application_name, None)
        return None
    return raw_token


def set_active_app_token(application_name: str, raw_token: str) -> None:
    _ACTIVE_APP_TOKENS[application_name] = raw_token
