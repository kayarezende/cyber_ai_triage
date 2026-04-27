"""wk-8 writeback + approval surface + detection_rules / hitl_policies uniqueness

Revision ID: d3a9f2c1e7b4
Revises: c1d8e3f4a9b2
Create Date: 2026-04-27

Wk-8 adds:

1. **Writeback + approval surface on `investigations`** — the LangGraph
   `writeback_node` records HEC + (optional) `notable_update` outcomes;
   `await_approval_node` records the analyst decision. `approver_id` is
   the application-level mirror written from state (the existing
   `human_approved_by` FK is set when the approver row exists in `users`).

2. **`detection_rule_matches` JSONB on `investigations`** — populated by
   `apply_detection_rules_node` (post-`review`) so the evidence manifest
   + admin UI can render which rules fired and why.

3. **Uniqueness on `detection_rules.name` + `hitl_policies.name`** —
   partial unique indexes split per-tenant + global (`tenant_id IS NULL`)
   namespaces so seed scripts can `INSERT … ON CONFLICT … DO UPDATE`
   idempotently.

`incidents.status` CHECK already includes `'awaiting_approval'` (initial
schema). `investigations.human_approved_by/at` already exist. No changes
to those.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "d3a9f2c1e7b4"
down_revision: Union[str, Sequence[str], None] = "c1d8e3f4a9b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Writeback + approval columns on investigations.
    op.execute(
        """
        ALTER TABLE investigations
          ADD COLUMN writeback_status TEXT
            CHECK (writeback_status IS NULL
                   OR writeback_status IN ('pending','succeeded','failed','skipped')),
          ADD COLUMN writeback_attempts JSONB NOT NULL DEFAULT '[]'::jsonb,
          ADD COLUMN approval_status TEXT
            CHECK (approval_status IS NULL
                   OR approval_status IN ('pending','approved','rejected','auto')),
          ADD COLUMN approver_id UUID,
          ADD COLUMN approval_notes TEXT,
          ADD COLUMN detection_rule_matches JSONB
        """
    )

    # 2. Partial unique indexes for detection_rules + hitl_policies.
    op.execute(
        """
        CREATE UNIQUE INDEX detection_rules_global_name_uq
          ON detection_rules (name) WHERE tenant_id IS NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX detection_rules_tenant_name_uq
          ON detection_rules (tenant_id, name) WHERE tenant_id IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX hitl_policies_global_name_uq
          ON hitl_policies (name) WHERE tenant_id IS NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX hitl_policies_tenant_name_uq
          ON hitl_policies (tenant_id, name) WHERE tenant_id IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS hitl_policies_tenant_name_uq")
    op.execute("DROP INDEX IF EXISTS hitl_policies_global_name_uq")
    op.execute("DROP INDEX IF EXISTS detection_rules_tenant_name_uq")
    op.execute("DROP INDEX IF EXISTS detection_rules_global_name_uq")
    op.execute(
        """
        ALTER TABLE investigations
          DROP COLUMN IF EXISTS detection_rule_matches,
          DROP COLUMN IF EXISTS approval_notes,
          DROP COLUMN IF EXISTS approver_id,
          DROP COLUMN IF EXISTS approval_status,
          DROP COLUMN IF EXISTS writeback_attempts,
          DROP COLUMN IF EXISTS writeback_status
        """
    )
