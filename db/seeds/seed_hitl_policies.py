"""Wk-8 seed: default global HITL policy.

Inserts one global (`tenant_id IS NULL`) policy named
`default_require_approval` with expression `{"op": "always_true"}`. Per
ADR-0009 the MVP requires human approval for every Tier-2 escalation;
tenant-specific lower-priority rules can opt out for narrow conditions.

The wk-8 migration adds a partial unique index on `(name) WHERE
tenant_id IS NULL` so this script is idempotent.

Run as DB owner / superuser so the RLS WITH CHECK clause permits
`tenant_id IS NULL` inserts.

Usage:
    uv run python db/seeds/seed_hitl_policies.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import psycopg

_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _resolve_dsn() -> str:
    """Prefer MIGRATION_DATABASE_URL — seeds need superuser perms (cluster A
    migration `e5f7a1b9c4d6` split app vs. migration DSNs)."""
    _load_dotenv(_ROOT / ".env")
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


_DEFAULT_POLICY_NAME = "default_require_approval"
_DEFAULT_POLICY_EXPR = {"op": "always_true"}
_DEFAULT_PRIORITY = 1000

_UPSERT_SQL = """
    INSERT INTO hitl_policies
        (tenant_id, name, rule_expression, priority, enabled)
    VALUES (NULL, %s, %s::jsonb, %s, TRUE)
    ON CONFLICT (name) WHERE tenant_id IS NULL DO UPDATE SET
        rule_expression = EXCLUDED.rule_expression,
        priority        = EXCLUDED.priority,
        enabled         = TRUE
"""


def main() -> int:
    dsn = _resolve_dsn()
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            _UPSERT_SQL,
            (
                _DEFAULT_POLICY_NAME,
                json.dumps(_DEFAULT_POLICY_EXPR),
                _DEFAULT_PRIORITY,
            ),
        )
        cur.execute("SELECT COUNT(*) FROM hitl_policies WHERE tenant_id IS NULL")
        row = cur.fetchone()
        total = int(row[0]) if row else 0
        conn.commit()
    print(f"seeded default HITL policy {_DEFAULT_POLICY_NAME!r} " f"(global rows: {total})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
