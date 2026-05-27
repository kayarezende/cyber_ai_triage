"""provider_credentials — admin-managed, encrypted per-provider LLM API keys

Revision ID: d9f3a1c0e7b2
Revises: c8e4d2a6b9f3
Create Date: 2026-05-27

Multi-provider LLM routing (Groq / Gemini / Anthropic-direct alongside
OpenRouter) needs per-provider API keys that are NOT baked into code or env.
This table stores them Fernet-encrypted (`sentient_common.crypto`, ADR-0012),
managed from Admin → Provider keys. One row per (tenant, provider). The
ciphertext lives in `key_encrypted`; `key_last4` is a non-sensitive hint shown
in the UI so an admin can recognise which key is set without ever reading it
back.

RLS: tenant-scoped, strict policy (USING + WITH CHECK identical) matching the
`STRICT_TENANT_TABLES` pattern from b7c4e9a2f1d8. DML grants for `app_runtime`
are provided automatically by the `ALTER DEFAULT PRIVILEGES` set in
e5f7a1b9c4d6 (this table is created by the migration superuser).
"""
from typing import Sequence, Union

from alembic import op


revision: str = "d9f3a1c0e7b2"
down_revision: Union[str, Sequence[str], None] = "c8e4d2a6b9f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE provider_credentials (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES tenants(id),
            provider TEXT NOT NULL
                CHECK (provider IN ('openrouter','groq','gemini','anthropic')),
            key_encrypted BYTEA NOT NULL,
            key_last4 TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(tenant_id, provider)
        )
        """
    )
    op.execute("ALTER TABLE provider_credentials ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON provider_credentials
          USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
          WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON provider_credentials")
    op.execute("ALTER TABLE provider_credentials DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE IF EXISTS provider_credentials")
