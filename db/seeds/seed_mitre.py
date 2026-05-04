"""Seed the mitre_techniques table from MITRE ATT&CK STIX 2.1.

Source: https://raw.githubusercontent.com/mitre-attack/attack-stix-data
Cache:  db/seeds/cache/enterprise-attack.json (gitignored)
Schema: see db/migrations/versions/81e2d43b3ec0_initial_schema.py

Idempotent: INSERT ... ON CONFLICT (technique_id) DO UPDATE. Re-running the
script picks up upstream additions / corrections without wiping existing rows.

Usage:
    uv run python db/seeds/seed_mitre.py            # use cache if present
    uv run python db/seeds/seed_mitre.py --refresh  # force re-download
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Json

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
_ROOT = Path(__file__).resolve().parents[2]
_CACHE = Path(__file__).resolve().parent / "cache" / "enterprise-attack.json"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so this script can run from the host without
    depending on python-dotenv. Mirrors db/seeds/setup_checkpointer.py."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _resolve_dsn() -> str:
    """Seeds need superuser perms (DDL-adjacent INSERTs on global tables);
    prefer MIGRATION_DATABASE_URL, fall back to DATABASE_URL only if the
    deployment hasn't split them (cluster A migration `e5f7a1b9c4d6`)."""
    _load_dotenv(_ROOT / ".env")
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    # psycopg native DSN — strip SQLAlchemy driver prefix if present.
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


def _fetch(refresh: bool) -> dict[str, Any]:
    if refresh or not _CACHE.exists():
        _CACHE.parent.mkdir(parents=True, exist_ok=True)
        print(f"fetching {SOURCE_URL}", file=sys.stderr)
        with urllib.request.urlopen(SOURCE_URL, timeout=60) as resp:  # noqa: S310
            data = resp.read()
        _CACHE.write_bytes(data)
    parsed: dict[str, Any] = json.loads(_CACHE.read_bytes())
    return parsed


def _extract_technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if isinstance(external_id, str):
                return external_id
    return None


def _extract_tactics(obj: dict[str, Any]) -> list[str]:
    return [
        kcp["phase_name"]
        for kcp in obj.get("kill_chain_phases", [])
        if kcp.get("kill_chain_name") == "mitre-attack" and isinstance(kcp.get("phase_name"), str)
    ]


def _rows(bundle: dict[str, Any]) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        technique_id = _extract_technique_id(obj)
        if technique_id is None:
            continue
        rows.append(
            (
                technique_id,
                _extract_tactics(obj),
                obj.get("name"),
                obj.get("description"),
                obj.get("x_mitre_platforms", []),
                obj.get("x_mitre_data_sources", []),
                obj.get("x_mitre_detection"),
                Json(obj),
            )
        )
    return rows


_UPSERT_SQL = """
    INSERT INTO mitre_techniques (
        technique_id, tactic_ids, name, description,
        platforms, data_sources, detection, raw
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (technique_id) DO UPDATE SET
        tactic_ids   = EXCLUDED.tactic_ids,
        name         = EXCLUDED.name,
        description  = EXCLUDED.description,
        platforms    = EXCLUDED.platforms,
        data_sources = EXCLUDED.data_sources,
        detection    = EXCLUDED.detection,
        raw          = EXCLUDED.raw
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed MITRE ATT&CK techniques.")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Re-download the STIX bundle even if cached.",
    )
    args = parser.parse_args(argv)

    bundle = _fetch(args.refresh)
    rows = _rows(bundle)
    if not rows:
        print("no attack-pattern objects found — aborting", file=sys.stderr)
        return 1

    dsn = _resolve_dsn()
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.executemany(_UPSERT_SQL, rows)
        cur.execute("SELECT COUNT(*) FROM mitre_techniques")
        row = cur.fetchone()
        total = int(row[0]) if row else 0
        conn.commit()

    print(f"seeded {len(rows)} techniques (total in table: {total})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
