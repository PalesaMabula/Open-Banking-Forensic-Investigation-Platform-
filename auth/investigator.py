import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from database.database import (
    get_connection,
    get_investigator_by_username,
    get_investigator_by_username_any_status,
    get_investigator_by_id,
    get_max_investigator_sequence,
    insert_investigator,
    update_investigator_fields,
)
import config

SESSION_LIFETIME_MINUTES = 120

ALLOWED_ROLES = {"Lead Investigator", "Forensic Analyst"}
ALLOWED_STATUSES = {"ACTIVE", "INACTIVE"}

DEMO_INVESTIGATORS = [
    {
        "investigator_id": "INV-001",
        "display_name": "Investigator 001",
        "role": "Lead Investigator",
        "username_env": "OBFIR_INV001_USERNAME",
        "password_env": "OBFIR_INV001_PASSWORD",
    },
    {
        "investigator_id": "INV-002",
        "display_name": "Investigator 002",
        "role": "Forensic Analyst",
        "username_env": "OBFIR_INV002_USERNAME",
        "password_env": "OBFIR_INV002_PASSWORD",
    },
]

# In-memory session store for investigators



_INVESTIGATOR_SESSIONS: dict[str, dict] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


## Investigator authentication and session management

def hash_password(password: str) -> str:
   
    salt = "obfir-investigator-salt"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


# ensures that the investigator table has at least the two demo investigators, using the usernames/passwords from .env

def seed_demo_investigators() -> None:
   
    conn = get_connection()
    cursor = conn.cursor()

    for inv_def in DEMO_INVESTIGATORS:
        cursor.execute(
            "SELECT COUNT(*) FROM investigators WHERE investigator_id = ?",
            (inv_def["investigator_id"],),
        )
        if cursor.fetchone()[0] > 0:
            continue

        username = getattr(config, inv_def["username_env"])
        password = getattr(config, inv_def["password_env"])

        if not username or not password:
            conn.close()
            raise RuntimeError(
                f"{inv_def['username_env']} and {inv_def['password_env']} must be "
                f"set in .env to seed '{inv_def['display_name']}'."
            )

        cursor.execute(
            """
            INSERT INTO investigators (
                investigator_id, display_name, role, username,
                password_hash, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inv_def["investigator_id"],
                inv_def["display_name"],
                inv_def["role"],
                username,
                hash_password(password),
                "ACTIVE",
                _utc_now().isoformat(),
            ),
        )

    conn.commit()
    conn.close()


# Investigator authentication and session management
def authenticate_investigator(username: str, password: str) -> dict | None:
 
    investigator = get_investigator_by_username(username)
    if investigator is None:
        return None
    if investigator["password_hash"] != hash_password(password):
        return None
    return investigator


def create_investigator_session(investigator_id: str) -> str:
    session_token = secrets.token_urlsafe(32)
    expires_at = _utc_now() + timedelta(minutes=SESSION_LIFETIME_MINUTES)
    _INVESTIGATOR_SESSIONS[session_token] = {
        "investigator_id": investigator_id,
        "expires_at": expires_at,
    }
    return session_token

# validates a session token and returns the full investigator recordor or None if the session is missingor expired
def get_investigator_from_session(session_token: str) -> dict | None:
 
    session = _INVESTIGATOR_SESSIONS.get(session_token)
    if session is None:
        return None
    if _utc_now() > session["expires_at"]:
        _INVESTIGATOR_SESSIONS.pop(session_token, None)
        return None
    return get_investigator_by_id(session["investigator_id"])


def end_investigator_session(session_token: str) -> None:
    _INVESTIGATOR_SESSIONS.pop(session_token, None)


def generate_investigator_id() -> str:
   
    next_seq = get_max_investigator_sequence() + 1
    return f"INV-{next_seq:03d}"


def create_investigator(
    display_name: str,
    username: str,
    password: str,
    role: str,
    status: str = "ACTIVE",
) -> dict:
    """
    Creates a new investigator account with a freshly generated,
    stable investigator_id. Raises ValueError (caller translates to a
    400 response) for an unsupported role/status or a username that
    is already in use by ANY investigator, active or not.
    """
    if role not in ALLOWED_ROLES:
        raise ValueError(f"Unsupported role: {role}")
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"Unsupported status: {status}")
    if not display_name.strip():
        raise ValueError("Display name is required.")
    if not username.strip():
        raise ValueError("Username is required.")
    if not password:
        raise ValueError("Password is required.")

    if get_investigator_by_username_any_status(username) is not None:
        raise ValueError("An investigator with this username already exists.")

    investigator_id = generate_investigator_id()

    insert_investigator(
        {
            "investigator_id": investigator_id,
            "display_name": display_name.strip(),
            "role": role,
            "username": username.strip(),
            "password_hash": hash_password(password),
            "status": status,
            "created_at": _utc_now().isoformat(),
        }
    )

    return get_investigator_by_id(investigator_id)

# Updates an investigator's display name and status 

def update_investigator(
    investigator_id: str,
    display_name: str | None = None,
    role: str | None = None,
    status: str | None = None,
) -> dict | None:
   
    if role is not None and role not in ALLOWED_ROLES:
        raise ValueError(f"Unsupported role: {role}")
    if status is not None and status not in ALLOWED_STATUSES:
        raise ValueError(f"Unsupported status: {status}")

    return update_investigator_fields(investigator_id, display_name, role, status)
