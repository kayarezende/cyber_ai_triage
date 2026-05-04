"""app_runtime role + audit hardening (cluster A bug-fix)

Revision ID: e5f7a1b9c4d6
Revises: d3a9f2c1e7b4
Create Date: 2026-05-04

Cluster A of the 2026-05-04 multi-agent codebase review. ADR-0017 protections
existed on paper only — the app connected as Postgres superuser, so RLS was
bypassed and `audit_log` UPDATE/DELETE/TRUNCATE triggers could be skipped.
Four findings folded into one migration since they share the trigger function:

* CRIT-1: provision a non-superuser `app_runtime` LOGIN role; the app DSN
  switches over in this commit. Direct table grants + `audit_writer`
  membership (INHERIT) cover writes; RLS now actually applies because
  `app_runtime` lacks `BYPASSRLS`.
* CRIT-2: add `BEFORE TRUNCATE` trigger on `audit_log` (existing trigger
  set covers UPDATE/DELETE only — TRUNCATE silently succeeded).
* CRIT-4: serialize concurrent INSERTs into the same `hash_scope` via
  `pg_advisory_xact_lock` inside `compute_audit_hash()`. Without this,
  parallel inserts could read the same `prev_hash` and fork the chain.
* MED-6: bind `hash_scope` into the digest so a row can't be moved between
  scopes without detection. Python helper `compute_audit_row_hash` is
  updated in lockstep — kw-only `hash_scope` parameter forces every call
  site to pass it.

`app_runtime`'s password is read from `APP_RUNTIME_PASSWORD` at upgrade time;
the migration aborts if unset. `POSTGRES_DB` (default `sentient`) is read
similarly so `POSTGRES_DB` overrides don't break the GRANT.

`audit_log` only receives INSERT + SELECT for `app_runtime` — UPDATE/DELETE
are blocked at the privilege layer in addition to the existing triggers
(belt-and-braces). All other tenant tables get full DML.

Cold-start gate (sidecar `migrate` service in compose) is intentionally
out of scope here — see `tasks/bug-fixes-2026-05-04/cluster-a-compliance.md`
Carry-forward.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "e5f7a1b9c4d6"
down_revision: str | Sequence[str] | None = "d3a9f2c1e7b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Tables app_runtime needs full DML on. audit_log is handled separately
# (INSERT + SELECT only) so UPDATE/DELETE attempts fail at privilege check
# before the append-only triggers ever fire.
DML_TABLES: tuple[str, ...] = (
    "tenants",
    "users",
    "llm_role_config",
    "incidents",
    "investigations",
    "usage",
    "mitre_techniques",
    "detection_rules",
    "hitl_policies",
)


def upgrade() -> None:
    password = os.environ.get("APP_RUNTIME_PASSWORD")
    if not password:
        msg = (
            "APP_RUNTIME_PASSWORD is required to create the app_runtime role. "
            "Set it in .env (or your migration shell) before running this migration."
        )
        raise RuntimeError(msg)
    db_name = os.environ.get("POSTGRES_DB", "sentient")

    # 1. Create app_runtime (LOGIN, default INHERIT so audit_writer membership
    #    grants real privileges, not just a SET ROLE handle). Idempotent so
    #    re-runs after a partial-rollback don't fail.
    bind = op.get_bind()
    bind.execute(
        text("""
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
                EXECUTE format('CREATE ROLE app_runtime LOGIN PASSWORD %L', :pw);
              ELSE
                EXECUTE format('ALTER ROLE app_runtime LOGIN PASSWORD %L', :pw);
              END IF;
            END
            $$
            """),
        {"pw": password},
    )

    # 2. Connect + schema usage. Quote db_name defensively.
    op.execute(f'GRANT CONNECT ON DATABASE "{db_name}" TO app_runtime')
    op.execute("GRANT USAGE ON SCHEMA public TO app_runtime")

    # 3. Per-table DML grants. audit_log gets INSERT+SELECT only; the
    #    audit_writer membership (step 5) is the documented path even though
    #    the direct grants would be enough — keeps the role intent explicit.
    for table in DML_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_runtime")
    op.execute("GRANT SELECT, INSERT ON audit_log TO app_runtime")

    # 4. Sequence usage (audit_log_id_seq, usage_id_seq, etc.).
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime")

    # 5. Audit-writer membership (audit_writer was created in b7c4e9a2f1d8).
    op.execute("GRANT audit_writer TO app_runtime")

    # 6. CRIT-2: TRUNCATE trigger. block_audit_modify() already exists from
    #    b7c4e9a2f1d8 — same function rejects with 'audit_log is append-only'.
    op.execute("""
        CREATE TRIGGER audit_log_no_truncate
          BEFORE TRUNCATE ON audit_log
          FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify()
        """)

    # 7. CRIT-4 + MED-6: replace compute_audit_hash() with advisory-locked
    #    + scope-bound digest. CREATE OR REPLACE preserves the existing
    #    audit_log_hash_trigger binding.
    op.execute("""
        CREATE OR REPLACE FUNCTION compute_audit_hash() RETURNS TRIGGER AS $$
        DECLARE
          prev_hash TEXT;
        BEGIN
          -- KEEP IN SYNC with libs/common/src/sentient_common/audit.py::compute_audit_row_hash.
          -- Advisory lock serializes concurrent inserts into the same hash_scope so
          -- two transactions can't read the same prev_hash and fork the chain. The
          -- lock is per-txn (released at commit/rollback). hashtext() collapses to
          -- int32 — collisions over-lock but never under-lock; correctness preserved.
          PERFORM pg_advisory_xact_lock(hashtext('audit_log:' || COALESCE(NEW.hash_scope, '')));

          SELECT content_hash INTO prev_hash
            FROM audit_log
            WHERE hash_scope = NEW.hash_scope
            ORDER BY id DESC
            LIMIT 1;
          NEW.previous_hash := COALESCE(prev_hash, '');
          NEW.content_hash := encode(
            digest(
              COALESCE(NEW.hash_scope, '') || '|' ||
              COALESCE(NEW.tenant_id::text, '') || '|' ||
              COALESCE(NEW.investigation_id::text, '') || '|' ||
              COALESCE(NEW.actor, '') || '|' ||
              COALESCE(NEW.action, '') || '|' ||
              COALESCE(NEW.details::text, '') || '|' ||
              COALESCE(NEW.created_at::text, '') || '|' ||
              NEW.previous_hash,
              'sha256'
            ),
            'hex'
          );
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """)


def downgrade() -> None:
    db_name = os.environ.get("POSTGRES_DB", "sentient")

    # 7. Restore the original compute_audit_hash() body (no advisory lock,
    #    no hash_scope in digest) — verbatim from b7c4e9a2f1d8.
    op.execute("""
        CREATE OR REPLACE FUNCTION compute_audit_hash() RETURNS TRIGGER AS $$
        DECLARE
          prev_hash TEXT;
        BEGIN
          SELECT content_hash INTO prev_hash
            FROM audit_log
            WHERE hash_scope = NEW.hash_scope
            ORDER BY id DESC
            LIMIT 1;
          NEW.previous_hash := COALESCE(prev_hash, '');
          NEW.content_hash := encode(
            digest(
              COALESCE(NEW.tenant_id::text, '') || '|' ||
              COALESCE(NEW.investigation_id::text, '') || '|' ||
              COALESCE(NEW.actor, '') || '|' ||
              COALESCE(NEW.action, '') || '|' ||
              COALESCE(NEW.details::text, '') || '|' ||
              COALESCE(NEW.created_at::text, '') || '|' ||
              NEW.previous_hash,
              'sha256'
            ),
            'hex'
          );
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """)

    # 6. Drop TRUNCATE trigger.
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")

    # 5. Drop audit_writer membership.
    op.execute("REVOKE audit_writer FROM app_runtime")

    # 4. Sequence revoke.
    op.execute("REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM app_runtime")

    # 3. Per-table revokes.
    op.execute("REVOKE ALL ON audit_log FROM app_runtime")
    for table in DML_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM app_runtime")

    # 2. Schema + connect.
    op.execute("REVOKE USAGE ON SCHEMA public FROM app_runtime")
    op.execute(f'REVOKE CONNECT ON DATABASE "{db_name}" FROM app_runtime')

    # 1. Defensive ownership reassign before DROP ROLE — required if any
    #    object ended up owned by app_runtime (shouldn't happen, but safe).
    op.execute("REASSIGN OWNED BY app_runtime TO postgres")
    op.execute("DROP OWNED BY app_runtime")
    op.execute("DROP ROLE IF EXISTS app_runtime")
