"""Seed the dev tenant referenced by `apps/api/src/sentient_api/settings.py:DEV_TENANT_ID`.

Idempotent — `INSERT ... ON CONFLICT (id) DO NOTHING`. Run after `alembic upgrade
head` so the `tenants` schema (incl. `writeback_mode` from b7c4e9a2f1d8) exists.

The dev tenant is hardcoded with `writeback_mode='hec_only'` because the founder's
local Splunk box is base Splunk Enterprise (no ES) — `dual` mode requires the ES
`notable_update` REST endpoint per ADR-0018. Flip via SQL when ES lands.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

DEV_TENANT_ID = "00000000-0000-0000-0000-000000000001"


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
    _load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


def main() -> int:
    dsn = _resolve_dsn()
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (id, name, writeback_mode)
                VALUES (%s, %s, 'hec_only')
                ON CONFLICT (id) DO NOTHING
                """,
                (DEV_TENANT_ID, "Dev Tenant"),
            )
            inserted = cur.rowcount
    if inserted:
        print(f"dev tenant {DEV_TENANT_ID} created.")
    else:
        print(f"dev tenant {DEV_TENANT_ID} already present. ok.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
