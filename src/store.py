"""SQLite persistence for findings, Devin sessions, scan runs, and webhook dedupe."""

import json
import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    class TEXT NOT NULL,
    package TEXT,
    current_version TEXT,
    fixed_version TEXT,
    cve_id TEXT,
    severity TEXT NOT NULL,
    file_path TEXT,
    summary TEXT NOT NULL,
    seeded INTEGER NOT NULL DEFAULT 0,
    issue_number INTEGER,
    issue_url TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    devin_session_id TEXT NOT NULL,
    devin_url TEXT NOT NULL,
    state TEXT NOT NULL,
    pr_url TEXT,
    ci_conclusion TEXT,
    ci_retries INTEGER NOT NULL DEFAULT 0,
    acu_used REAL NOT NULL DEFAULT 0,
    human_messages_sent INTEGER NOT NULL DEFAULT 0,
    structured_output TEXT,
    created_at REAL NOT NULL,
    terminal_at REAL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    trigger TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    sessions_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    received_at REAL NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_finding(conn: sqlite3.Connection, *, fingerprint: str, source: str,
                    finding_class: str, severity: str, summary: str,
                    package: str | None = None, current_version: str | None = None,
                    fixed_version: str | None = None, cve_id: str | None = None,
                    file_path: str | None = None, seeded: bool = False) -> str:
    """Insert a finding, or return the existing id if this fingerprint was already seen."""
    existing = get_finding_by_fingerprint(conn, fingerprint)
    if existing:
        return existing["id"]

    finding_id = str(uuid.uuid4())
    now = time.time()
    conn.execute(
        """INSERT INTO findings
           (id, fingerprint, source, class, package, current_version, fixed_version,
            cve_id, severity, file_path, summary, seeded, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)""",
        (finding_id, fingerprint, source, finding_class, package, current_version,
         fixed_version, cve_id, severity, file_path, summary, int(seeded), now, now),
    )
    conn.commit()
    return finding_id


def get_finding_by_fingerprint(conn: sqlite3.Connection, fingerprint: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()


def get_finding(conn: sqlite3.Connection, finding_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()


def update_finding_status(conn: sqlite3.Connection, finding_id: str, status: str) -> None:
    conn.execute(
        "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
        (status, time.time(), finding_id),
    )
    conn.commit()


def set_finding_issue(conn: sqlite3.Connection, finding_id: str, *,
                       issue_number: int, issue_url: str) -> None:
    conn.execute(
        "UPDATE findings SET issue_number = ?, issue_url = ?, updated_at = ? WHERE id = ?",
        (issue_number, issue_url, time.time(), finding_id),
    )
    conn.commit()


def upsert_session(conn: sqlite3.Connection, *, session_id: str | None,
                    state: str, finding_id: str | None = None,
                    devin_session_id: str | None = None, devin_url: str | None = None,
                    pr_url: str | None = None, ci_conclusion: str | None = None,
                    ci_retries: int = 0, acu_used: float = 0,
                    human_messages_sent: int = 0,
                    structured_output: dict | None = None,
                    terminal: bool = False) -> str:
    """Create a session row if session_id is None, otherwise update the existing one.

    finding_id/devin_session_id/devin_url are only required to create a row -
    an update never touches them, so callers updating an existing session
    don't need to pass placeholder values for fields that won't be used.
    """
    now = time.time()
    output_json = json.dumps(structured_output) if structured_output is not None else None

    if session_id is None:
        if not (finding_id and devin_session_id and devin_url):
            raise ValueError("finding_id, devin_session_id, and devin_url are required to create a session")
        session_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO sessions
               (id, finding_id, devin_session_id, devin_url, state, pr_url, ci_conclusion,
                ci_retries, acu_used, human_messages_sent, structured_output,
                created_at, terminal_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, finding_id, devin_session_id, devin_url, state, pr_url,
             ci_conclusion, ci_retries, acu_used, human_messages_sent, output_json,
             now, now if terminal else None),
        )
    else:
        conn.execute(
            """UPDATE sessions SET state = ?, pr_url = ?, ci_conclusion = ?, ci_retries = ?,
               acu_used = ?, human_messages_sent = ?, structured_output = ?, terminal_at = ?
               WHERE id = ?""",
            (state, pr_url, ci_conclusion, ci_retries, acu_used, human_messages_sent,
             output_json, now if terminal else None, session_id),
        )
    conn.commit()
    return session_id


def get_session(conn: sqlite3.Connection, session_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()


def start_run(conn: sqlite3.Connection, trigger: str) -> str:
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO runs (id, trigger, started_at) VALUES (?, ?, ?)",
        (run_id, trigger, time.time()),
    )
    conn.commit()
    return run_id


def finish_run(conn: sqlite3.Connection, run_id: str, *, findings_count: int, sessions_count: int) -> None:
    conn.execute(
        "UPDATE runs SET finished_at = ?, findings_count = ?, sessions_count = ? WHERE id = ?",
        (time.time(), findings_count, sessions_count, run_id),
    )
    conn.commit()


def record_delivery(conn: sqlite3.Connection, delivery_id: str) -> bool:
    """Record a webhook delivery. Returns True if new, False if this delivery_id was already seen."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO deliveries (delivery_id, received_at) VALUES (?, ?)",
        (delivery_id, time.time()),
    )
    conn.commit()
    return cur.rowcount > 0
