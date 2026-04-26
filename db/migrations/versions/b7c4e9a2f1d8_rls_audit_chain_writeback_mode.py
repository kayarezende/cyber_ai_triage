"""rls hardening + audit hash chain + writeback_mode + sovereignty hybrid cols

Revision ID: b7c4e9a2f1d8
Revises: 81e2d43b3ec0
Create Date: 2026-04-27

Wk-2 cleanup pass per review feedback. Three concerns rolled into one migration:

1. **RLS — global rules visibility (P1).** Initial schema's `tenant_isolation` policy
   on `detection_rules` + `hitl_policies` excludes `tenant_id IS NULL` rows (NULL never
   equals anything). Recreate those two with `IS NULL OR ...`. Add `WITH CHECK` to all
   tenant-scoped tables to prevent cross-tenant inserts via missing/wrong session var.

2. **Audit hash chain (P2).** Initial schema had `content_hash` column + a comment.
   Add `previous_hash` + `hash_scope`. BEFORE INSERT trigger computes both. BEFORE
   UPDATE/DELETE triggers raise. Per-investigation chain partition (`hash_scope`).
   `audit_writer` DB role with INSERT + SELECT only. See ADR-0017.

3. **Splunk `writeback_mode` + sovereignty hybrid columns.** Per-tenant config for
   `dual` vs `hec_only` writeback (default `hec_only` — works on plain Splunk
   Enterprise; ES tenants flip to `dual`). Plus dormant columns for sovereign-mode
   tier (BYO LLM keys, region constraint, langsmith toggle). See ADR-0016, ADR-0018.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "b7c4e9a2f1d8"
down_revision: Union[str, Sequence[str], None] = "81e2d43b3ec0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Tenant-scoped tables that use a strict policy (USING + WITH CHECK identical).
# tenant_id is the column key; rows with NULL tenant_id are not allowed at app level.
STRICT_TENANT_TABLES: tuple[str, ...] = (
    "users",
    "llm_role_config",
    "incidents",
    "investigations",
    "audit_log",
    "usage",
)

# Tenant-scoped tables where tenant_id IS NULL means "global" (visible to all tenants).
# USING is permissive (NULL OR match); WITH CHECK is strict (no NULL inserts from app role).
GLOBAL_CAPABLE_TENANT_TABLES: tuple[str, ...] = (
    "detection_rules",
    "hitl_policies",
)


def upgrade() -> None:
    # 1. RLS — recreate policies with WITH CHECK and NULL-handling where needed.
    for table in STRICT_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
              WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )

    for table in GLOBAL_CAPABLE_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant', true)::uuid)
              WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )

    # 2. Audit hash chain — columns + index + triggers + role.
    op.execute(
        """
        ALTER TABLE audit_log
          ADD COLUMN previous_hash TEXT,
          ADD COLUMN hash_scope TEXT
        """
    )
    op.execute(
        "CREATE INDEX audit_log_hash_scope_id_idx ON audit_log (hash_scope, id)"
    )

    op.execute(
        """
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
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_hash_trigger
          BEFORE INSERT ON audit_log
          FOR EACH ROW EXECUTE FUNCTION compute_audit_hash()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION block_audit_modify() RETURNS TRIGGER AS $$
        BEGIN
          RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
          BEFORE UPDATE ON audit_log
          FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_delete
          BEFORE DELETE ON audit_log
          FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify()
        """
    )

    # `digest()` lives in pgcrypto — already created by the initial schema migration.
    # Idempotent guard in case someone runs this migration on a DB without it.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # audit_writer role: INSERT + SELECT (SELECT needed for trigger's prev_hash lookup).
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
            CREATE ROLE audit_writer NOLOGIN;
          END IF;
        END
        $$
        """
    )
    op.execute("GRANT INSERT ON audit_log TO audit_writer")
    op.execute("GRANT SELECT ON audit_log TO audit_writer")
    op.execute("GRANT USAGE ON SEQUENCE audit_log_id_seq TO audit_writer")

    # 3. tenants table: writeback_mode (ADR-0018) + sovereignty hybrid cols (ADR-0016).
    op.execute(
        """
        ALTER TABLE tenants
          ADD COLUMN writeback_mode TEXT
            CHECK (writeback_mode IN ('dual', 'hec_only'))
            DEFAULT 'hec_only',
          ADD COLUMN byo_openrouter_key_encrypted BYTEA,
          ADD COLUMN byo_anthropic_key_encrypted BYTEA,
          ADD COLUMN llm_region_constraint TEXT,
          ADD COLUMN langsmith_enabled BOOLEAN DEFAULT TRUE
        """
    )


def downgrade() -> None:
    # Reverse order of upgrade.

    # 3. tenants — drop hybrid cols + writeback_mode.
    op.execute(
        """
        ALTER TABLE tenants
          DROP COLUMN IF EXISTS langsmith_enabled,
          DROP COLUMN IF EXISTS llm_region_constraint,
          DROP COLUMN IF EXISTS byo_anthropic_key_encrypted,
          DROP COLUMN IF EXISTS byo_openrouter_key_encrypted,
          DROP COLUMN IF EXISTS writeback_mode
        """
    )

    # 2. Audit hash chain — drop role, triggers, functions, index, columns.
    op.execute("REVOKE INSERT ON audit_log FROM audit_writer")
    op.execute("REVOKE SELECT ON audit_log FROM audit_writer")
    op.execute("REVOKE USAGE ON SEQUENCE audit_log_id_seq FROM audit_writer")
    op.execute("DROP ROLE IF EXISTS audit_writer")

    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS block_audit_modify()")

    op.execute("DROP TRIGGER IF EXISTS audit_log_hash_trigger ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS compute_audit_hash()")

    op.execute("DROP INDEX IF EXISTS audit_log_hash_scope_id_idx")
    op.execute(
        """
        ALTER TABLE audit_log
          DROP COLUMN IF EXISTS hash_scope,
          DROP COLUMN IF EXISTS previous_hash
        """
    )

    # 1. Restore prior RLS policies (no WITH CHECK; strict-only for all 8 tables).
    for table in (*STRICT_TENANT_TABLES, *GLOBAL_CAPABLE_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )
