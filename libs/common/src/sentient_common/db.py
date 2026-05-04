"""SQLAlchemy engine + tenant-scoped session helper.

`tenant_session(tenant_id)` opens a transaction, switches the connection's
role to `app_runtime` (the non-superuser app role provisioned by migration
`e5f7a1b9c4d6`), and `SET LOCAL app.current_tenant` so RLS policies
(`b7c4e9a2f1d8`) are enforced. The `LOCAL` qualifier ties both bindings to
the txn — exiting commits or rolls back, and the role + var reset to the
session role/empty automatically.

`SET LOCAL ROLE` is the load-bearing security control: superuser sessions
bypass RLS regardless of `app.current_tenant`. The DSN authenticates as
`app_runtime`; this `SET LOCAL ROLE` is belt-and-braces in case the DSN
is ever misconfigured back to the superuser.

Constraint: callers must not nest `tenant_session(...)` inside an outer
`engine.connect()` block. `engine.begin()` would start a SAVEPOINT, and
`SET LOCAL ROLE` resets at savepoint release rather than the outer txn
commit. No call site does this today; if a future caller needs it, lift
the role/tenant binding into the outer txn explicitly.
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
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError(
            "DATABASE_URL is not set. Refusing to fall back to a superuser "
            "default — the app must connect as app_runtime for RLS to apply."
        )
    return create_engine(dsn, pool_pre_ping=True, future=True)


def get_engine() -> Engine:
    """Process-wide cached SQLAlchemy engine for `DATABASE_URL`."""
    with _engine_lock:
        return _build_engine()


@contextmanager
def tenant_session(tenant_id: UUID) -> Iterator[Connection]:
    """Open a connection inside `engine.begin()`, bind tenant + role, yield.

    Order is intentional: the tenant GUC is set first so even if the role
    switch is ever short-circuited, RLS would still apply (assuming the
    DSN is non-superuser). Commits on clean exit; rolls back on exception.
    Use for every read/write path that touches a tenant-scoped table.
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        conn.execute(text("SET LOCAL ROLE app_runtime"))
        yield conn


__all__ = ["get_engine", "tenant_session"]
