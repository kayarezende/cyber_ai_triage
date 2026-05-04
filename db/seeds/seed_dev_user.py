"""Seed the dev user referenced by web `DEV_USER_ID` + dev-bypass middleware.

The Web's middleware sets ``x-user-id: 00000000-0000-0000-0000-0000000000aa``
when ``DEV_BYPASS_AUTH=1`` (see `apps/web/src/middleware.ts`). The API
approval router optionally writes ``investigations.human_approved_by``,
which has a FK into ``users.id``. Pre-seed: the FK was silently dropped and
approvals showed NULL approver. Post-seed: the FK resolves and the approver
chain is recorded.

Idempotent — ``INSERT ... ON CONFLICT (id) DO NOTHING``. Runs after
``seed_tenants`` (FK target).

Replaced when wk-11 Entra SSO lands; the dev-bypass user becomes a
fixture flagged behind ``DEV_BYPASS_AUTH``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

DEV_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEV_USER_ID = "00000000-0000-0000-0000-0000000000aa"
DEV_USER_EMAIL = "dev@sentientlayer.ai"
DEV_USER_ROLE = "admin"


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
                INSERT INTO users (id, tenant_id, email, role)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (DEV_USER_ID, DEV_TENANT_ID, DEV_USER_EMAIL, DEV_USER_ROLE),
            )
            inserted = cur.rowcount
    if inserted:
        print(f"dev user {DEV_USER_ID} ({DEV_USER_EMAIL}, {DEV_USER_ROLE}) created.")
    else:
        print(f"dev user {DEV_USER_ID} already present. ok.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
