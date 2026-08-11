"""
Storage dispatcher for the CPEDS-X auth layer.

Chooses the user store at runtime and forwards every call to it:

    * Supabase (Postgres)  -> when SUPABASE_URL and SUPABASE_KEY are both set.
                              Use this in production (Render + Vercel) because
                              Render's free filesystem is ephemeral — a local
                              SQLite file is wiped on every cold start/redeploy.
    * SQLite (stdlib)      -> otherwise. Zero setup, perfect for local dev.

The public surface is unchanged, so routes.py / security.py don't know or care
which backend is active. All stores return plain dicts and raise the shared
DuplicateEmailError on a duplicate signup, so callers stay storage-agnostic.

Force a specific backend (optional):
    AUTH_STORE=sqlite    or    AUTH_STORE=supabase
"""
import os

from ._store_base import DuplicateEmailError  # re-exported for routes.py

_store = None


def _select_store():
    """Pick the concrete store module based on environment configuration."""
    forced = (os.environ.get("AUTH_STORE") or "").strip().lower()
    have_supabase = bool(
        os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_KEY")
    )

    if forced == "sqlite":
        use_supabase = False
    elif forced == "supabase":
        use_supabase = True
    else:
        use_supabase = have_supabase  # auto-detect

    if use_supabase:
        from . import _store_supabase as store
    else:
        from . import _store_sqlite as store
    return store


def _get_store():
    """Lazily resolve and cache the active store (first call wins)."""
    global _store
    if _store is None:
        _store = _select_store()
        print(f"[CPEDS-X] Auth storage backend: {_store.BACKEND_NAME}")
    return _store


def active_backend() -> str:
    """Name of the active store ('sqlite' or 'supabase'). Useful for /health."""
    return _get_store().BACKEND_NAME


# ------------------------------------------------------------------
# Forwarders — identical signatures to the underlying store functions.
# ------------------------------------------------------------------
def init_db() -> None:
    return _get_store().init_db()


def get_user_by_email(email):
    return _get_store().get_user_by_email(email)


def get_user_by_id(user_id):
    return _get_store().get_user_by_id(user_id)


def create_user(email, full_name, password_hash):
    return _get_store().create_user(email, full_name, password_hash)


def update_password(email, new_hash):
    return _get_store().update_password(email, new_hash)


def create_reset_token(email, token, expires_at):
    return _get_store().create_reset_token(email, token, expires_at)


def get_reset_token(token):
    return _get_store().get_reset_token(token)


def mark_reset_used(token):
    return _get_store().mark_reset_used(token)


# ------------------------------------------------------------------
# Incidents (detection history) — per-user isolated.
# ------------------------------------------------------------------
def create_incident(user_id, incident):
    return _get_store().create_incident(user_id, incident)


def list_incidents(user_id, limit=200):
    return _get_store().list_incidents(user_id, limit)


def get_incident(user_id, incident_id):
    return _get_store().get_incident(user_id, incident_id)


def update_incident(user_id, incident_id, fields):
    return _get_store().update_incident(user_id, incident_id, fields)


def clear_incidents(user_id):
    return _get_store().clear_incidents(user_id)


__all__ = [
    "DuplicateEmailError",
    "active_backend",
    "init_db",
    "get_user_by_email",
    "get_user_by_id",
    "create_user",
    "update_password",
    "create_reset_token",
    "get_reset_token",
    "mark_reset_used",
    "create_incident",
    "list_incidents",
    "get_incident",
    "update_incident",
    "clear_incidents",
]
