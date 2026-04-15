"""initial schema

Revision ID: 81e2d43b3ec0
Revises:
Create Date: 2026-04-15

Creates the 10 core application tables and enables RLS on tenant-scoped
tables with a missing-ok `current_setting('app.current_tenant', true)` policy.
Policies are defined now; application code does not SET app.current_tenant
until wk 4, so superuser/owner sessions (including Alembic + seeds) bypass RLS.

LangGraph checkpointer tables (checkpoint_migrations, checkpoints,
checkpoint_blobs, checkpoint_writes) are NOT managed here — created by
db/seeds/setup_checkpointer.py.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "81e2d43b3ec0"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_SCOPED_TABLES: tuple[str, ...] = (
    "users",
    "llm_role_config",
    "incidents",
    "investigations",
    "audit_log",
    "usage",
    "detection_rules",
    "hitl_policies",
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.execute(
        """
        CREATE TABLE tenants (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            splunk_host TEXT,
            splunk_token_encrypted BYTEA,
            splunk_hec_token_encrypted BYTEA,
            max_concurrent_investigations INT DEFAULT 5,
            monthly_llm_budget_usd NUMERIC(10,2),
            per_investigation_budget_usd NUMERIC(10,4),
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID REFERENCES tenants(id),
            email TEXT,
            role TEXT CHECK (role IN ('analyst','admin')),
            entra_oid TEXT UNIQUE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        CREATE TABLE llm_role_config (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID REFERENCES tenants(id),
            role TEXT CHECK (role IN ('triage','investigation','review','summarize','entity_extraction')),
            primary_model TEXT NOT NULL,
            fallback_chain TEXT[] DEFAULT '{}',
            max_tokens INT DEFAULT 4096,
            temperature NUMERIC(3,2) DEFAULT 0.2,
            timeout_seconds INT DEFAULT 30,
            enabled BOOLEAN DEFAULT TRUE,
            UNIQUE(tenant_id, role)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID REFERENCES tenants(id),
            siem_source TEXT DEFAULT 'splunk',
            siem_notable_id TEXT,
            received_at TIMESTAMPTZ DEFAULT NOW(),
            raw_payload_s3_key TEXT,
            ocsf_normalized JSONB,
            status TEXT CHECK (status IN ('new','triaging','investigating','awaiting_approval','done','failed','inconclusive'))
        )
        """
    )

    op.execute(
        """
        CREATE TABLE investigations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID,
            incident_id UUID REFERENCES incidents(id),
            langgraph_thread_id TEXT,
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            verdict TEXT CHECK (verdict IN ('true_positive','false_positive','benign','inconclusive')),
            confidence NUMERIC(3,2),
            severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
            mitre_techniques TEXT[],
            summary TEXT,
            evidence_s3_key TEXT,
            ocsf_output JSONB,
            review_notes TEXT,
            human_approved_by UUID REFERENCES users(id),
            human_approved_at TIMESTAMPTZ,
            inconclusive_reason TEXT
        )
        """
    )

    op.execute(
        """
        CREATE TABLE audit_log (
            id BIGSERIAL PRIMARY KEY,
            tenant_id UUID,
            investigation_id UUID,
            actor TEXT,
            action TEXT,
            details JSONB,
            content_hash TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        CREATE TABLE usage (
            id BIGSERIAL PRIMARY KEY,
            tenant_id UUID,
            investigation_id UUID,
            role TEXT,
            attempt_num INT,
            model_requested TEXT,
            model_used TEXT,
            status TEXT CHECK (status IN ('success','timeout','5xx','validation_fail','rate_limited')),
            input_tokens INT,
            output_tokens INT,
            cached_tokens INT,
            cost_usd NUMERIC(10,6),
            openrouter_generation_id TEXT,
            latency_ms INT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        CREATE TABLE mitre_techniques (
            technique_id TEXT PRIMARY KEY,
            tactic_ids TEXT[],
            name TEXT,
            description TEXT,
            platforms TEXT[],
            data_sources TEXT[],
            detection TEXT,
            raw JSONB
        )
        """
    )

    op.execute(
        """
        CREATE TABLE detection_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID,
            name TEXT,
            description TEXT,
            required_techniques TEXT[],
            any_techniques TEXT[],
            severity_override TEXT,
            enabled BOOLEAN DEFAULT TRUE
        )
        """
    )

    op.execute(
        """
        CREATE TABLE hitl_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID REFERENCES tenants(id),
            name TEXT,
            rule_expression JSONB,
            priority INT DEFAULT 100,
            enabled BOOLEAN DEFAULT TRUE
        )
        """
    )

    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )


def downgrade() -> None:
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP TABLE IF EXISTS hitl_policies")
    op.execute("DROP TABLE IF EXISTS detection_rules")
    op.execute("DROP TABLE IF EXISTS mitre_techniques")
    op.execute("DROP TABLE IF EXISTS usage")
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS investigations")
    op.execute("DROP TABLE IF EXISTS incidents")
    op.execute("DROP TABLE IF EXISTS llm_role_config")
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP TABLE IF EXISTS tenants")
