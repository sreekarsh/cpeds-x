-- ============================================================
-- CPEDS-X — Supabase / Postgres schema for the auth layer
-- ============================================================
-- Run this ONCE in your Supabase project:
--   Supabase Dashboard -> SQL Editor -> New query -> paste -> Run.
--
-- It creates the two tables the backend expects and locks them down with
-- Row Level Security so the public anon key cannot read or write them. The
-- backend talks to these tables with the service_role key, which bypasses RLS
-- by design — so credentials never travel through the browser.
-- ============================================================

-- ---- Users -------------------------------------------------
create table if not exists public.users (
    id            bigint generated always as identity primary key,
    email         text        not null,
    full_name     text        not null,
    password_hash text        not null,
    created_at    timestamptz not null default now()
);

-- Case-insensitive uniqueness on email (matches the app's lower-cased writes
-- and SQLite's COLLATE NOCASE behaviour).
create unique index if not exists users_email_lower_idx
    on public.users (lower(email));

-- ---- Password reset tokens ---------------------------------
create table if not exists public.password_resets (
    token      text        primary key,
    email      text        not null,
    expires_at bigint      not null,   -- epoch seconds (matches the backend)
    used       boolean     not null default false
);

create index if not exists password_resets_email_idx
    on public.password_resets (lower(email));

-- ---- Incidents (detection history) -------------------------
-- One row per detected event a SOC operator reviews (from the live simulator,
-- an uploaded log, or an attack scenario). Scoped to the owning user so each
-- operator only ever sees their own history. raw_log is jsonb so the full
-- CloudTrail event can be re-opened for a fresh XAI breakdown.
create table if not exists public.incidents (
    id              bigint generated always as identity primary key,
    user_id         bigint      not null references public.users (id) on delete cascade,
    created_at      timestamptz not null default now(),
    source          text        not null default 'manual',
    event_name      text,
    principal       text,
    source_ip       text,
    predicted_class integer     not null,
    class_label     text        not null,
    confidence      double precision not null,
    action_status   text        not null default 'MONITORED',
    raw_log         jsonb,
    rollback        jsonb
);

-- Migrate older projects created before live mode added the rollback column.
alter table public.incidents add column if not exists rollback jsonb;

-- Newest-first history lookups per operator.
create index if not exists incidents_user_idx
    on public.incidents (user_id, id desc);

-- ---- Lock the tables down ----------------------------------
-- With RLS enabled and NO policies, the anon/public key gets zero access.
-- The backend uses the service_role key, which bypasses RLS, so it still works.
alter table public.users            enable row level security;
alter table public.password_resets  enable row level security;
alter table public.incidents        enable row level security;

-- (Intentionally no policies: only the trusted backend service_role key may
-- touch these tables. Do not add anon policies unless you know you need them.)
