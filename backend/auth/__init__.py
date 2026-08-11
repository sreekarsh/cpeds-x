"""
CPEDS-X authentication package.

Provides real account-based auth for the SOC console:
  - Pluggable user store: SQLite (stdlib, local dev) or Supabase/Postgres
    (managed, for Render + Vercel hosting) — selected automatically from env.
  - Password hashing (bcrypt when available, PBKDF2-SHA256 fallback)
  - JWT session tokens (PyJWT when available, stdlib HS256 fallback)
  - FastAPI router + dependency to gate the ML endpoints

Storage is chosen at runtime by database.py: if SUPABASE_URL and SUPABASE_KEY
are set it uses Supabase, otherwise a local SQLite file. Both stores expose the
same functions and return plain dicts, so the rest of the app is agnostic.

The package still runs with ZERO extra installs for local dev (stdlib
fallbacks + SQLite), and transparently upgrades to bcrypt/PyJWT/Supabase when
those are present.
"""
