"""Create LangGraph Postgres checkpointer tables.

Idempotent. Run after `alembic upgrade head`. Creates four tables that Alembic
does NOT manage:
    checkpoint_migrations, checkpoints, checkpoint_blobs, checkpoint_writes

The Postgres connection DSN for PostgresSaver uses psycopg's native format
(postgresql://...), NOT SQLAlchemy's (postgresql+psycopg://...). We strip the
SQLAlchemy driver suffix from DATABASE_URL if present.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from langgraph.checkpoint.postgres import PostgresSaver


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
    with PostgresSaver.from_conn_string(dsn) as checkpointer:
        checkpointer.setup()
    print("checkpointer setup complete: 4 tables created or already present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
