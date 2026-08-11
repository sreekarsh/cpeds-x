"""
SQLite-backed user store (local development default).

Uses the Python stdlib `sqlite3` module — no database server, no extra installs.
A connection is opened per operation, which keeps things thread-safe under
FastAPI/uvicorn without extra configuration.

All functions return plain `dict`s (not sqlite3.Row) so the store is
interchangeable with the Supabase store, which returns dicts too.

Tables
------
users            : registered SOC operators
password_resets  : short-lived, single-use reset tokens
incidents        : detected threats (per operator), for the history view
"""
import json
import os
import sqlite3
from typing import Optional

from ._store_base import DuplicateEmailError, utc_now_iso

# DB file lives in the backend/ directory (two levels up from auth/_store_sqlite.py).
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cpeds_users.db"
)

BACKEND_NAME = "sqlite"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> Optional[dict]:
    return dict(row) if row is not None else None


def init_db() -> None:
    """Create tables if they do not yet exist. Safe to call on every startup."""
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                full_name     TEXT    NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                token      TEXT    PRIMARY KEY,
                email      TEXT    NOT NULL COLLATE NOCASE,
                expires_at INTEGER NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL,
                created_at      TEXT    NOT NULL,
                source          TEXT    NOT NULL,
                event_name      TEXT,
                principal       TEXT,
                source_ip       TEXT,
                predicted_class INTEGER NOT NULL,
                class_label     TEXT    NOT NULL,
                confidence      REAL    NOT NULL,
                action_status   TEXT    NOT NULL,
                raw_log         TEXT,
                rollback        TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_user "
            "ON incidents (user_id, id DESC)"
        )
        # Auto-migrate older DBs that predate the live-mode rollback column.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        if "rollback" not in cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN rollback TEXT")
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# Users
# ------------------------------------------------------------------
def get_user_by_email(email: str) -> Optional[dict]:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)
        )
        return _row_to_dict(cur.fetchone())
    finally:
        conn.close()


def get_user_by_id(user_id) -> Optional[dict]:
    conn = _connect()
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return _row_to_dict(cur.fetchone())
    finally:
        conn.close()


def create_user(email: str, full_name: str, password_hash: str) -> dict:
    """Insert a new user. Raises DuplicateEmailError if the email exists."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, full_name, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (email.strip().lower(), full_name.strip(), password_hash, utc_now_iso()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return dict(row)
    except sqlite3.IntegrityError as e:
        raise DuplicateEmailError(str(e))
    finally:
        conn.close()


def update_password(email: str, new_hash: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE email = ? COLLATE NOCASE",
            (new_hash, email),
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# Password reset tokens
# ------------------------------------------------------------------
def create_reset_token(email: str, token: str, expires_at: int) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO password_resets (token, email, expires_at, used) "
            "VALUES (?, ?, ?, 0)",
            (token, email, expires_at),
        )
        conn.commit()
    finally:
        conn.close()


def get_reset_token(token: str) -> Optional[dict]:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM password_resets WHERE token = ?", (token,)
        )
        return _row_to_dict(cur.fetchone())
    finally:
        conn.close()


def mark_reset_used(token: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE password_resets SET used = 1 WHERE token = ?", (token,)
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# Incidents (detection history)
# ------------------------------------------------------------------
def _incident_row_to_dict(row) -> Optional[dict]:
    if row is None:
        return None
    d = dict(row)
    # raw_log is stored as a JSON string; hydrate it back to a dict.
    if d.get("raw_log"):
        try:
            d["raw_log"] = json.loads(d["raw_log"])
        except (ValueError, TypeError):
            d["raw_log"] = None
    # rollback token is likewise stored as JSON text.
    if d.get("rollback"):
        try:
            d["rollback"] = json.loads(d["rollback"])
        except (ValueError, TypeError):
            d["rollback"] = None
    return d


def create_incident(user_id, incident: dict) -> dict:
    """Persist one detected incident for a user. Returns the stored row."""
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO incidents
              (user_id, created_at, source, event_name, principal, source_ip,
               predicted_class, class_label, confidence, action_status, raw_log,
               rollback)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                incident.get("created_at") or utc_now_iso(),
                incident.get("source", "manual"),
                incident.get("event_name", ""),
                incident.get("principal", ""),
                incident.get("source_ip", ""),
                int(incident.get("predicted_class", 0)),
                incident.get("class_label", ""),
                float(incident.get("confidence", 0.0)),
                incident.get("action_status", "MONITORED"),
                json.dumps(incident.get("raw_log")) if incident.get("raw_log") is not None else None,
                json.dumps(incident.get("rollback")) if incident.get("rollback") is not None else None,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return _incident_row_to_dict(row)
    finally:
        conn.close()


def update_incident(user_id, incident_id, fields: dict) -> Optional[dict]:
    """Update mutable fields (action_status, rollback) on one owned incident.

    Used by live mode to flip an incident to CONTAINED / REVERSED and to store
    or clear its rollback token. Scoped to the owner; returns the updated row.
    """
    allowed = {"action_status", "rollback"}
    sets, params = [], []
    for key in allowed:
        if key in fields:
            sets.append(f"{key} = ?")
            val = fields[key]
            if key == "rollback" and val is not None and not isinstance(val, str):
                val = json.dumps(val)
            params.append(val)
    if not sets:
        return get_incident(user_id, incident_id)
    params.extend([incident_id, user_id])
    conn = _connect()
    try:
        conn.execute(
            f"UPDATE incidents SET {', '.join(sets)} WHERE id = ? AND user_id = ?",
            params,
        )
        conn.commit()
    finally:
        conn.close()
    return get_incident(user_id, incident_id)


def list_incidents(user_id, limit: int = 200) -> list:
    """Return a user's incidents, newest first."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM incidents WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, int(limit)),
        )
        return [_incident_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_incident(user_id, incident_id) -> Optional[dict]:
    """Return one incident by id, scoped to the owning user."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT * FROM incidents WHERE id = ? AND user_id = ?",
            (incident_id, user_id),
        )
        return _incident_row_to_dict(cur.fetchone())
    finally:
        conn.close()


def clear_incidents(user_id) -> int:
    """Delete all of a user's incidents. Returns the number removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM incidents WHERE user_id = ?", (user_id,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
