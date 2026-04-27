"""SQLAlchemy engine + tenant-scoped session helper.

`tenant_session(tenant_id)` opens a transaction and `SET LOCAL app.current_tenant`
so RLS policies (migration `b7c4e9a2f1d8`) are enforced for that connection.
The `LOCAL` qualifier ties the binding to the txn — exiting commits or rolls
back, and the var resets automatically.

Note: Postgres superusers (the default `postgres` role) bypass RLS regardless
of `app.current_tenant`. Hardening to a non-superuser `app_role` is on the
wk-12 list; the policy still informs the schema today.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import Connection

_engine_lock = threading.Lock()


@lru_cache(maxsize=1)
def _build_engine() -> Engine:
    dsn = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/sentient",
    )
    return create_engine(dsn, pool_pre_ping=True, future=True)


def get_engine() -> Engine:
    """Process-wide cached SQLAlchemy engine for `DATABASE_URL`."""
    with _engine_lock:
        return _build_engine()


@contextmanager
def tenant_session(tenant_id: UUID) -> Iterator[Connection]:
    """Open a connection inside `engine.begin()`, bind `app.current_tenant`, yield.

    Commits on clean exit; rolls back on exception. Use for every write path that
    touches a tenant-scoped table.
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        yield conn


__all__ = ["get_engine", "tenant_session"]
