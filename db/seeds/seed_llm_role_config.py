"""Seed `llm_role_config` rows for every tenant.

Run after `seed_tenants.py`. Idempotent — `INSERT ... ON CONFLICT (tenant_id, role)
DO NOTHING` so admin edits via the wk-10 UI (or hand-SQL today) are not
overwritten on re-run.

Five rows per tenant per ADR-0010:

| role               | enabled (MVP) |
|--------------------|---------------|
| triage             | true          |
| investigation      | true          |
| review             | true          |
| summarize          | false         |
| entity_extraction  | false         |

All seed rows ship the MVP-dev primary model `google/gemini-3-flash-preview`
with empty fallback_chain — fail loud during wk-5 implementation; the
operator flips to a real fallback chain in prod via UI/SQL. See the wk-5
plan for the rationale.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

DEV_PRIMARY_MODEL = "google/gemini-3-flash-preview"

# (role, max_tokens, temperature, timeout_seconds, enabled)
_ROLE_DEFAULTS: tuple[tuple[str, int, float, int, bool], ...] = (
    ("triage", 1024, 0.0, 30, True),
    ("investigation", 4096, 0.2, 60, True),
    ("review", 2048, 0.0, 30, True),
    ("summarize", 1024, 0.2, 30, False),
    ("entity_extraction", 1024, 0.0, 30, False),
)


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
    dsn = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


def main() -> int:
    dsn = _resolve_dsn()
    inserted_total = 0
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM tenants")
            tenant_ids = [str(row[0]) for row in cur.fetchall()]
            if not tenant_ids:
                print("no tenants found — run seed_tenants.py first.")
                return 0
            for tenant_id in tenant_ids:
                for role, max_tokens, temperature, timeout, enabled in _ROLE_DEFAULTS:
                    cur.execute(
                        """
                        INSERT INTO llm_role_config
                            (tenant_id, role, primary_model, fallback_chain,
                             max_tokens, temperature, timeout_seconds, enabled)
                        VALUES
                            (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, role) DO NOTHING
                        """,
                        (
                            tenant_id,
                            role,
                            DEV_PRIMARY_MODEL,
                            [],
                            max_tokens,
                            temperature,
                            timeout,
                            enabled,
                        ),
                    )
                    inserted_total += cur.rowcount
    print(
        f"seeded llm_role_config for {len(tenant_ids)} tenants; "
        f"{inserted_total} rows inserted (existing rows preserved)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
