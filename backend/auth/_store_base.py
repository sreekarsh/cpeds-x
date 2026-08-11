"""
Shared, storage-agnostic pieces for the auth data layer.

This is a *leaf* module: it imports nothing from the rest of the auth package,
so both the SQLite and Supabase stores (and the database.py dispatcher) can
depend on it without creating an import cycle.
"""
from datetime import datetime, timezone


class DuplicateEmailError(Exception):
    """Raised by a store's create_user() when the email already exists.

    Storage-agnostic: routes.py catches this instead of a backend-specific
    exception (e.g. sqlite3.IntegrityError or a Postgres unique-violation),
    so the same handler works no matter which store is active.
    """


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string (used for created_at)."""
    return datetime.now(timezone.utc).isoformat()
