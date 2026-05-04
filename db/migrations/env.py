"""Alembic env.

Loads MIGRATION_DATABASE_URL (preferred) or DATABASE_URL from .env at repo
root via a manual python-dotenv-style parse (no runtime dep). Migrations
must run as a Postgres superuser to create roles, replace functions, and
own triggers; the app's own DSN points at the lower-privilege `app_runtime`
role from the `e5f7a1b9c4d6` migration onward, so the two DSNs are split.

Alembic manages only the application schema. LangGraph checkpointer tables
(checkpoint_migrations, checkpoints, checkpoint_blobs, checkpoint_writes)
are created separately by db/seeds/setup_checkpointer.py — do NOT
autogenerate against them.
"""

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv(Path(__file__).resolve().parents[2] / ".env")

config = context.config

database_url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError(
        "Neither MIGRATION_DATABASE_URL nor DATABASE_URL is set. "
        "Migrations must run as a superuser; set MIGRATION_DATABASE_URL "
        "(or DATABASE_URL if app and migrations share a DSN)."
    )
config.set_main_option("sqlalchemy.url", database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
