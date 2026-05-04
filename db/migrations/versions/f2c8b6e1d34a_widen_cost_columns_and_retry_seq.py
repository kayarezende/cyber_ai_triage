"""widen cost columns + add usage.retry_seq (cluster C bug-fix)

Revision ID: f2c8b6e1d34a
Revises: e5f7a1b9c4d6
Create Date: 2026-05-04

Cluster C of the 2026-05-04 multi-agent codebase review. Closes the
cost-cap evasion holes:

* HIGH-8: ``usage.cost_usd`` and ``investigations.total_cost_usd`` were
  ``NUMERIC(10,6)`` — capped at $9999.999999. A single high-spend
  investigation (Opus over a long tool-loop) can exceed that. Widen all
  three cost columns to ``NUMERIC(14,6)`` so the per-investigation cap
  is bounded by tenant config, not column width.

* CRIT-5: ``_validate_with_retry`` makes a second OpenRouter call
  inside one logical attempt. That call's tokens + cost were absent
  from the ``usage`` ledger and from the per-investigation accumulator
  — the cap was evadable indefinitely by triggering schema validation
  failures. Add ``usage.retry_seq INT NOT NULL DEFAULT 0`` so the retry
  HTTP call writes its own row distinguished from the primary by
  ``(attempt_num, retry_seq)``. ADR-0015 amended with the new identity.

* MED-1: ``cap_usd == 0`` previously raised on cost == 0 because the
  comparison is ``>=``. Add a column comment documenting that NULL or
  0 means "disabled" — the in-Python gate (``router._check_budget``)
  short-circuits on either; the column comment makes the convention
  discoverable for admins editing ``tenants`` directly.

Downgrade is guarded: any cost row exceeding the old NUMERIC(10,6)
range raises explicitly so an operator must narrow the data before
shrinking the column. Without the guard, ``ALTER TYPE`` would error
mid-statement with a less-actionable message.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f2c8b6e1d34a"
down_revision: str | Sequence[str] | None = "e5f7a1b9c4d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Widen cost columns. NUMERIC(14,6) lets us record up to
    #    $99,999,999.999999 — six orders of magnitude above any plausible
    #    per-investigation spend. Six decimals match OpenRouter's billing
    #    granularity (sub-cent per million tokens).
    op.execute("ALTER TABLE investigations ALTER COLUMN total_cost_usd TYPE NUMERIC(14,6)")
    op.execute("ALTER TABLE usage ALTER COLUMN cost_usd TYPE NUMERIC(14,6)")
    op.execute("ALTER TABLE tenants ALTER COLUMN per_investigation_budget_usd TYPE NUMERIC(14,6)")

    # 2. CRIT-5: per-attempt schema-retry sub-event marker. 0 = primary
    #    HTTP call (existing rows back-filled by DEFAULT 0); 1 = first
    #    schema-retry call inside the same _validate_with_retry pass;
    #    higher values reserved for future hardening (multi-retry).
    op.execute("ALTER TABLE usage ADD COLUMN retry_seq INT NOT NULL DEFAULT 0")

    # 3. MED-1 + audit ledger discoverability — column comments.
    op.execute(
        "COMMENT ON COLUMN tenants.per_investigation_budget_usd "
        "IS 'Per-investigation USD cap. NULL or 0 = disabled (no limit).'"
    )
    op.execute(
        "COMMENT ON COLUMN tenants.per_investigation_token_cap "
        "IS 'Per-investigation combined input+output token cap. NULL or 0 = disabled.'"
    )
    op.execute(
        "COMMENT ON COLUMN usage.retry_seq "
        "IS '0 = primary attempt; 1 = first schema-retry within same attempt_num. "
        "Composite identity with attempt_num distinguishes retry sub-events per ADR-0015.'"
    )


def downgrade() -> None:
    # Refuse to narrow if any row would overflow NUMERIC(10,6) (>9999.999999).
    # Without this guard, ALTER TYPE would error mid-statement; explicit
    # RAISE is more actionable for an operator.
    op.execute("""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM investigations WHERE total_cost_usd > 9999.999999)
             OR EXISTS (SELECT 1 FROM usage WHERE cost_usd > 9999.999999)
             OR EXISTS (SELECT 1 FROM tenants WHERE per_investigation_budget_usd > 9999.999999)
          THEN
            RAISE EXCEPTION
              'cannot downgrade f2c8b6e1d34a: cost values exceed NUMERIC(10,6) range; '
              'narrow data before downgrading';
          END IF;
        END
        $$
        """)

    op.execute("DROP INDEX IF EXISTS ix_usage_retry_seq")  # defensive — no index added but cheap
    op.execute("ALTER TABLE usage DROP COLUMN retry_seq")

    # Restore original column types. tenants.per_investigation_budget_usd
    # was NUMERIC(10,4) in the initial schema (81e2d43b3ec0) — the cost
    # columns elsewhere were (10,6). Restore both to their prior
    # precisions exactly.
    op.execute("ALTER TABLE tenants ALTER COLUMN per_investigation_budget_usd TYPE NUMERIC(10,4)")
    op.execute("ALTER TABLE usage ALTER COLUMN cost_usd TYPE NUMERIC(10,6)")
    op.execute("ALTER TABLE investigations ALTER COLUMN total_cost_usd TYPE NUMERIC(10,6)")

    # Comments are dropped automatically when the column type is altered if
    # the implementation re-creates; for safety re-issue NULL comment.
    op.execute("COMMENT ON COLUMN tenants.per_investigation_budget_usd IS NULL")
    op.execute("COMMENT ON COLUMN tenants.per_investigation_token_cap IS NULL")
