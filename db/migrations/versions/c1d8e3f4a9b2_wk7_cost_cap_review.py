"""wk-7 per-investigation cost cap accumulators + review surface

Revision ID: c1d8e3f4a9b2
Revises: b7c4e9a2f1d8
Create Date: 2026-04-27

Wk-7 adds:

1. **Cost / token accumulators on `investigations`** — running totals updated
   in the same transaction as `usage` row inserts, so the budget gate inside
   `LLMRouter` can SELECT a single row instead of SUM-ing the whole `usage`
   table on every call.

2. **Review surface on `investigations`** — `review_status` (approved /
   flagged / skipped) + `review_metadata` JSONB. `review_notes` already
   exists from the initial schema.

3. **`tenants.per_investigation_token_cap`** — companion to the existing
   `per_investigation_budget_usd`. Either NULL = cap disabled.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "c1d8e3f4a9b2"
down_revision: Union[str, Sequence[str], None] = "b7c4e9a2f1d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Accumulators + review surface on investigations.
    op.execute(
        """
        ALTER TABLE investigations
          ADD COLUMN total_input_tokens INT NOT NULL DEFAULT 0,
          ADD COLUMN total_output_tokens INT NOT NULL DEFAULT 0,
          ADD COLUMN total_cost_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
          ADD COLUMN review_status TEXT
            CHECK (review_status IS NULL
                   OR review_status IN ('approved','flagged','skipped')),
          ADD COLUMN review_metadata JSONB
        """
    )

    # 2. Token cap on tenants. USD cap (`per_investigation_budget_usd`) was
    #    added in the initial schema (81e2d43b3ec0).
    op.execute(
        """
        ALTER TABLE tenants
          ADD COLUMN per_investigation_token_cap INT
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE tenants
          DROP COLUMN IF EXISTS per_investigation_token_cap
        """
    )
    op.execute(
        """
        ALTER TABLE investigations
          DROP COLUMN IF EXISTS review_metadata,
          DROP COLUMN IF EXISTS review_status,
          DROP COLUMN IF EXISTS total_cost_usd,
          DROP COLUMN IF EXISTS total_output_tokens,
          DROP COLUMN IF EXISTS total_input_tokens
        """
    )
