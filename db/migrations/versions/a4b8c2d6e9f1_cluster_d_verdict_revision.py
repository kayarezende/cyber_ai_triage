"""add investigations.verdict_revision (cluster D HIGH-9)

Revision ID: a4b8c2d6e9f1
Revises: f2c8b6e1d34a
Create Date: 2026-05-04

Cluster D of the 2026-05-04 multi-agent codebase review. Closes HIGH-9
(HEC writeback not idempotent on resume) by giving each verdict a
monotonic revision number so the HEC payload carries a stable
``sentient_dedup_id = "{investigation_id}:{verdict_revision}"``.

Today every verdict is revision 1 — the column defaults to 1 and is
never bumped. The column exists so wk-12's reaper + future
verdict-correction flow can bump it without a schema migration; the
field also gives Splunk-side traceability when an analyst later asks
"why did this incident's HEC entry update?" without piggybacking on
``investigation_id`` alone.

The Splunk-side dedup is deferred — that's a founder-side index lookup
(or a Splunk dedup transform configured at the writeback index). The
column + payload field are the foundation it needs.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "a4b8c2d6e9f1"
down_revision: str | Sequence[str] | None = "f2c8b6e1d34a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE investigations " "ADD COLUMN verdict_revision INTEGER NOT NULL DEFAULT 1"
    )
    op.execute(
        "COMMENT ON COLUMN investigations.verdict_revision "
        "IS 'Monotonic verdict revision. Stable across resume; bumped only "
        "when the verdict text actually changes (deferred to wk-12). HEC "
        "payload includes sentient_dedup_id = investigation_id:verdict_revision "
        "so Splunk-side dedup can land on a stable key.'"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE investigations DROP COLUMN verdict_revision")
