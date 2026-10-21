import sqlite3
from config import DATABASE_PATH, DATA_DIR


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate_forensic_events_integrity_columns(cursor, conn) -> None:
    cursor.execute("PRAGMA table_info(forensic_events)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    if "previous_hash" not in existing_columns:
        cursor.execute("ALTER TABLE forensic_events ADD COLUMN previous_hash TEXT")

    if "event_hash" not in existing_columns:
        cursor.execute("ALTER TABLE forensic_events ADD COLUMN event_hash TEXT")

    conn.commit()


def _migrate_access_tokens_context_column(cursor, conn) -> None:
    cursor.execute("PRAGMA table_info(access_tokens)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    if "issued_context" not in existing_columns:
        cursor.execute("ALTER TABLE access_tokens ADD COLUMN issued_context TEXT")

    conn.commit()


def init_database() -> None:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_interactions (
            interaction_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            http_method TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            account_id TEXT,
            response_status INTEGER,
            source TEXT,
            destination TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS forensic_events (
            event_id TEXT PRIMARY KEY,
            interaction_id TEXT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_type TEXT,
            actor_id TEXT,
            account_id TEXT,
            details_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (interaction_id) REFERENCES api_interactions (interaction_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            application_id TEXT PRIMARY KEY,
            client_id TEXT UNIQUE NOT NULL,
            client_secret_hash TEXT NOT NULL,
            application_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_tokens (
            token_id TEXT PRIMARY KEY,
            application_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (application_id) REFERENCES applications (application_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consents (
            consent_id TEXT PRIMARY KEY,
            application_id TEXT NOT NULL,
            customer_id TEXT NOT NULL,
            account_id TEXT,
            permissions_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            authorized_at TEXT,
            expires_at TEXT,
            FOREIGN KEY (application_id) REFERENCES applications (application_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_events (
            custody_event_id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            from_holder TEXT,
            to_holder TEXT,
            reason TEXT,
            integrity_status TEXT,
            evidence_hash TEXT,
            previous_custody_hash TEXT,
            custody_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (evidence_id) REFERENCES forensic_events (event_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS forensic_findings (
            finding_id TEXT PRIMARY KEY,
            scenario_type TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            application_id TEXT,
            customer_id TEXT,
            account_id TEXT,
            consent_id TEXT,
            token_fingerprint TEXT,
            related_event_ids_json TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_metrics (
            metric_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            scenario_type TEXT,
            metric_name TEXT NOT NULL,
            metric_value REAL,
            metric_unit TEXT,
            calculated_at TEXT NOT NULL,
            details_json TEXT,
            FOREIGN KEY (finding_id) REFERENCES forensic_findings (finding_id),
            UNIQUE(finding_id, metric_name)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigators (
            investigator_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_reference TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            assigned_investigator_id TEXT,
            account_id TEXT,
            finding_id TEXT,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (assigned_investigator_id) REFERENCES investigators (investigator_id)
        )
    """)

    conn.commit()

    _migrate_forensic_events_integrity_columns(cursor, conn)
    _migrate_access_tokens_context_column(cursor, conn)

    conn.close()


def get_api_interactions() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_interactions ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_forensic_events() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_events ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_forensic_event_by_id(event_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_events WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_api_interaction_by_id(interaction_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM api_interactions WHERE interaction_id = ?", (interaction_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_application_by_id(application_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT application_id, client_id, application_name, status FROM applications WHERE application_id = ?",
        (application_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_applications() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT application_id, client_id, application_name, status FROM applications ORDER BY created_at ASC"
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_application_by_name(application_name: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT application_id, client_id, application_name, status FROM applications WHERE application_name = ?",
        (application_name,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

#login 
def get_investigator_by_username(username: str) -> dict | None:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM investigators WHERE username = ? AND status = 'ACTIVE'",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

#verify inveigator details 
def get_investigator_by_username_any_status(username: str) -> dict | None:
   
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigators WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_investigator_by_id(investigator_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM investigators WHERE investigator_id = ?", (investigator_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# reads all investigators
def get_all_investigators() -> list[dict]:
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT investigator_id, display_name, role, username, status FROM investigators ORDER BY created_at ASC"
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_max_investigator_sequence() -> int:
   
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT investigator_id FROM investigators")
    rows = cursor.fetchall()
    conn.close()

    max_seq = 0
    for (investigator_id,) in rows:
        if investigator_id and investigator_id.startswith("INV-"):
            suffix = investigator_id[4:]
            if suffix.isdigit():
                max_seq = max(max_seq, int(suffix))
    return max_seq


def insert_investigator(investigator: dict) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO investigators (
            investigator_id, display_name, role, username,
            password_hash, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            investigator["investigator_id"],
            investigator["display_name"],
            investigator["role"],
            investigator["username"],
            investigator["password_hash"],
            investigator["status"],
            investigator["created_at"],
        ),
    )
    conn.commit()
    conn.close()

# addind ivestigators detials 
def update_investigator_fields(
    investigator_id: str,
    display_name: str | None,
    role: str | None,
    status: str | None,
) -> dict | None:
   
    existing = get_investigator_by_id(investigator_id)
    if existing is None:
        return None

    new_display_name = (
        display_name if display_name is not None else existing["display_name"]
    )
    new_role = role if role is not None else existing["role"]
    new_status = status if status is not None else existing["status"]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE investigators SET display_name = ?, role = ?, status = ? WHERE investigator_id = ?",
        (new_display_name, new_role, new_status, investigator_id),
    )
    conn.commit()
    conn.close()
    return get_investigator_by_id(investigator_id)


def count_cases() -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cases")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def insert_case(case: dict) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO cases (
            case_id, case_reference, title, status, assigned_investigator_id,
            account_id, finding_id, description, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case["case_id"],
            case["case_reference"],
            case["title"],
            case["status"],
            case.get("assigned_investigator_id"),
            case.get("account_id"),
            case.get("finding_id"),
            case.get("description"),
            case["created_at"],
            case["updated_at"],
        ),
    )
    conn.commit()
    conn.close()


def get_case_by_id(case_id: str) -> dict | None:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_cases() -> list[dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def update_case_assignment(
    case_id: str, new_investigator_id: str, updated_at: str
) -> dict | None:
    existing = get_case_by_id(case_id)
    if existing is None:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cases SET assigned_investigator_id = ?, updated_at = ? WHERE case_id = ?",
        (new_investigator_id, updated_at, case_id),
    )
    conn.commit()
    conn.close()
    return get_case_by_id(case_id)


def update_case_status(case_id: str, new_status: str, updated_at: str) -> dict | None:
    existing = get_case_by_id(case_id)
    if existing is None:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
        (new_status, updated_at, case_id),
    )
    conn.commit()
    conn.close()
    return get_case_by_id(case_id)
