"""
Supabase-backed user store (production: Render + Vercel).

Talks to Supabase Postgres through the official `supabase` Python client
(PostgREST under the hood). Selected automatically by database.py when both
SUPABASE_URL and SUPABASE_KEY are set in the environment.

Why Supabase for hosting
------------------------
Render's free instances have an ephemeral filesystem (a local SQLite file is
wiped on every cold start / redeploy), and Vercel serverless functions can't
persist local files at all. Supabase gives a managed Postgres database on its
free tier that survives restarts, so user accounts actually stick.

Setup (once)
------------
1. Create a free project at https://supabase.com.
2. In the SQL editor, run backend/supabase_schema.sql (creates the two tables
   and enables Row Level Security).
3. Project Settings -> API: copy the Project URL and the **service_role** key.
4. Set env vars on the backend host (Render):
       SUPABASE_URL = https://<ref>.supabase.co
       SUPABASE_KEY = <service_role key>   # secret; backend only, never the frontend
   The service_role key bypasses RLS, which is exactly what a trusted backend
   wants; the public anon key cannot touch these tables.

All functions return plain dicts, matching the SQLite store, so the rest of the
auth package is agnostic to which backend is active.
"""
import os
from typing import Optional

from ._store_base import DuplicateEmailError, utc_now_iso

_USERS = "users"
_RESETS = "password_resets"
_INCIDENTS = "incidents"

BACKEND_NAME = "supabase"

# Lazily-created singleton client (created on first use, not at import time).
_client_singleton = None


def _client():
    """Create (once) and return the Supabase client.

    Imported lazily so the `supabase` package is only required when Supabase is
    actually the selected backend — local dev on SQLite needs nothing installed.
    """
    global _client_singleton
    if _client_singleton is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_KEY must both be set to use the "
                "Supabase store."
            )
        try:
            from supabase import create_client  # type: ignore
        except Exception as e:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "The 'supabase' package is not installed. Add it with "
                "`pip install supabase` (it's in requirements.txt), or unset "
                "SUPABASE_URL/SUPABASE_KEY to fall back to local SQLite."
            ) from e
        _client_singleton = create_client(url, key)
    return _client_singleton


def _is_duplicate_error(err: Exception) -> bool:
    """Detect a Postgres unique-violation across supabase/postgrest versions."""
    code = getattr(err, "code", None)
    if code == "23505":
        return True
    text = str(getattr(err, "message", "") or "") + " " + str(err)
    text = text.lower()
    return "23505" in text or "duplicate key" in text or "already exists" in text


def _first(resp) -> Optional[dict]:
    """Return the first row of an execute() response, or None."""
    data = getattr(resp, "data", None)
    if not data:
        return None
    return data[0]


def init_db() -> None:
    """
    No-op schema check for Supabase.

    Tables are created once via backend/supabase_schema.sql in the Supabase SQL
    editor (PostgREST can't run DDL). Here we just probe connectivity and print
    a clear, actionable message if the table is missing — without crashing the
    app, so the error also surfaces cleanly on the first auth request.
    """
    try:
        _client().table(_USERS).select("id").limit(1).execute()
        print("[CPEDS-X] Supabase store connected (users table reachable).")
    except Exception as e:  # pragma: no cover - depends on live project
        print(
            "[CPEDS-X][WARN] Could not reach the Supabase 'users' table: "
            f"{e}\n"
            "  -> Confirm SUPABASE_URL / SUPABASE_KEY (service_role) are correct "
            "and that you ran backend/supabase_schema.sql in the SQL editor."
        )


# ------------------------------------------------------------------
# Users
# ------------------------------------------------------------------
def get_user_by_email(email: str) -> Optional[dict]:
    resp = (
        _client()
        .table(_USERS)
        .select("*")
        .eq("email", email.strip().lower())
        .limit(1)
        .execute()
    )
    return _first(resp)


def get_user_by_id(user_id) -> Optional[dict]:
    resp = _client().table(_USERS).select("*").eq("id", user_id).limit(1).execute()
    return _first(resp)


def create_user(email: str, full_name: str, password_hash: str) -> dict:
    """Insert a new user. Raises DuplicateEmailError if the email exists."""
    payload = {
        "email": email.strip().lower(),
        "full_name": full_name.strip(),
        "password_hash": password_hash,
        "created_at": utc_now_iso(),
    }
    try:
        resp = _client().table(_USERS).insert(payload).execute()
    except Exception as e:
        if _is_duplicate_error(e):
            raise DuplicateEmailError(str(e))
        raise
    row = _first(resp)
    if row is None:
        # Some client versions return no rows on insert unless asked; re-fetch.
        row = get_user_by_email(payload["email"])
    return row


def update_password(email: str, new_hash: str) -> None:
    _client().table(_USERS).update({"password_hash": new_hash}).eq(
        "email", email.strip().lower()
    ).execute()


# ------------------------------------------------------------------
# Password reset tokens
# ------------------------------------------------------------------
def create_reset_token(email: str, token: str, expires_at: int) -> None:
    _client().table(_RESETS).upsert(
        {
            "token": token,
            "email": email.strip().lower(),
            "expires_at": int(expires_at),
            "used": False,
        }
    ).execute()


def get_reset_token(token: str) -> Optional[dict]:
    resp = (
        _client().table(_RESETS).select("*").eq("token", token).limit(1).execute()
    )
    return _first(resp)


def mark_reset_used(token: str) -> None:
    _client().table(_RESETS).update({"used": True}).eq("token", token).execute()


# ------------------------------------------------------------------
# Incidents (detection history)
# ------------------------------------------------------------------
def create_incident(user_id, incident: dict) -> dict:
    """Persist one detected incident for a user. Returns the stored row.

    raw_log and rollback are stored in Postgres jsonb columns, so the dicts are
    passed through as-is (no manual json.dumps — PostgREST serializes them).
    """
    payload = {
        "user_id": user_id,
        "created_at": incident.get("created_at") or utc_now_iso(),
        "source": incident.get("source", "manual"),
        "event_name": incident.get("event_name", ""),
        "principal": incident.get("principal", ""),
        "source_ip": incident.get("source_ip", ""),
        "predicted_class": int(incident.get("predicted_class", 0)),
        "class_label": incident.get("class_label", ""),
        "confidence": float(incident.get("confidence", 0.0)),
        "action_status": incident.get("action_status", "MONITORED"),
        "raw_log": incident.get("raw_log"),
        "rollback": incident.get("rollback"),
    }
    resp = _client().table(_INCIDENTS).insert(payload).execute()
    return _first(resp) or payload


def update_incident(user_id, incident_id, fields: dict) -> Optional[dict]:
    """Update mutable fields (action_status, rollback) on one owned incident."""
    allowed = {"action_status", "rollback"}
    update = {k: v for k, v in fields.items() if k in allowed}
    if not update:
        return get_incident(user_id, incident_id)
    resp = (
        _client()
        .table(_INCIDENTS)
        .update(update)
        .eq("id", incident_id)
        .eq("user_id", user_id)
        .execute()
    )
    return _first(resp) or get_incident(user_id, incident_id)


def list_incidents(user_id, limit: int = 200) -> list:
    """Return a user's incidents, newest first."""
    resp = (
        _client()
        .table(_INCIDENTS)
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .limit(int(limit))
        .execute()
    )
    return getattr(resp, "data", None) or []


def get_incident(user_id, incident_id) -> Optional[dict]:
    """Return one incident by id, scoped to the owning user."""
    resp = (
        _client()
        .table(_INCIDENTS)
        .select("*")
        .eq("id", incident_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    return _first(resp)


def clear_incidents(user_id) -> int:
    """Delete all of a user's incidents. Returns the number removed."""
    resp = (
        _client()
        .table(_INCIDENTS)
        .delete()
        .eq("user_id", user_id)
        .execute()
    )
    return len(getattr(resp, "data", None) or [])
