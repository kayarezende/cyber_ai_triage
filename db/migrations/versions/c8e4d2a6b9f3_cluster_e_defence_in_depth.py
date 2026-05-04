"""cluster E defence in depth (audit_chain_gap + length CHECKs)

Revision ID: c8e4d2a6b9f3
Revises: a4b8c2d6e9f1
Create Date: 2026-05-04

Cluster E of the 2026-05-04 multi-agent codebase review. Defence-in-depth
layer that doesn't fail today on benign inputs but breaks under adversarial
or pathological conditions.

* HIGH-12: ``audit_chain_gap`` table records audit emit failures so
  ``verify_chain`` cannot accept a partial chain as intact. Plain table —
  no triggers, no RLS — admin-surface only. Indexed by tenant_id +
  created_at for the wk-11 dashboard surface.
* HIGH-11 + MED-14: belt-and-braces SQL CHECK constraints on
  ``investigations.review_notes`` and ``investigations.approval_notes``
  (≤ 1024 chars). The application-side truncation is the primary defence;
  these constraints catch any future code path that bypasses the helpers.

Grants for ``app_runtime`` (introduced in ``e5f7a1b9c4d6``) are explicit
INSERT + SELECT — UPDATE/DELETE not granted because rows are append-only
and the wk-11 dashboard only ever reads + writes new rows.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "c8e4d2a6b9f3"
down_revision: str | Sequence[str] | None = "a4b8c2d6e9f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. audit_chain_gap — best-effort ledger of audit emit failures.
    #    investigation_id is nullable: tenant-scope emits (e.g. ingest
    #    pipeline) carry no investigation_id but their failure must still
    #    be recorded.
    op.execute(
        """
        CREATE TABLE audit_chain_gap (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            investigation_id UUID NULL,
            attempted_action TEXT NOT NULL,
            error_message TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        "CREATE INDEX idx_audit_chain_gap_tenant_created "
        "ON audit_chain_gap (tenant_id, created_at DESC)"
    )

    # 2. app_runtime grants. e5f7a1b9c4d6 set ALTER DEFAULT PRIVILEGES on
    #    future tables in public, so app_runtime already has the full DML
    #    grant via that path. Re-apply INSERT + SELECT explicitly + REVOKE
    #    UPDATE/DELETE to keep the role intent precise: this table is
    #    append-only (modulo a wk-12 reaper that, if added, will run as
    #    superuser).
    op.execute("REVOKE ALL ON audit_chain_gap FROM app_runtime")
    op.execute("GRANT SELECT, INSERT ON audit_chain_gap TO app_runtime")

    # 3. CHECK constraints — HIGH-11 review_notes_len + MED-14
    #    approval_notes_len. NOT VALID would let the constraint apply to
    #    new rows without scanning existing ones, but the dev DB is fresh
    #    enough that a full scan is cheap; production migrations on real
    #    data would use NOT VALID + VALIDATE in two steps.
    op.execute(
        "ALTER TABLE investigations "
        "ADD CONSTRAINT review_notes_len "
        "CHECK (review_notes IS NULL OR length(review_notes) <= 1024)"
    )
    op.execute(
        "ALTER TABLE investigations "
        "ADD CONSTRAINT approval_notes_len "
        "CHECK (approval_notes IS NULL OR length(approval_notes) <= 1024)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE investigations DROP CONSTRAINT IF EXISTS approval_notes_len")
    op.execute("ALTER TABLE investigations DROP CONSTRAINT IF EXISTS review_notes_len")
    op.execute("DROP INDEX IF EXISTS idx_audit_chain_gap_tenant_created")
    op.execute("DROP TABLE IF EXISTS audit_chain_gap")
