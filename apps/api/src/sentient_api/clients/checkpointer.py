"""Lifespan-managed AsyncPostgresSaver for the wk-9 replay endpoints.

Opening a fresh `AsyncPostgresSaver.from_conn_string()` per request churns
psycopg connection pools; the replay UI auto-refreshes a list view, which
makes that churn visible. Stash a single saver + pool on `app.state` for
the FastAPI process lifetime.

The orchestrator + worker still open per-run savers (one per resume / one
per investigation) — they have very different lifecycle semantics (graph
context attaches MCP tools, runs once, releases). Sharing a saver across
those would tangle pool lifetimes with graph runs. Keep the API-side
saver scoped to read-only replay queries.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg_pool import AsyncConnectionPool

from sentient_common.logging import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI

log = get_logger(__name__)

_POOL_MIN = 1
_POOL_MAX = 8


def _strip_psycopg_dsn(database_url: str) -> str:
    """`AsyncConnectionPool` wants the libpq form, not SQLAlchemy's `+psycopg`."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


async def open_checkpointer(app: FastAPI) -> None:
    """Open the pool + saver during FastAPI lifespan startup.

    Idempotent. Failure to open is non-fatal — the replay endpoints will
    return 503 until the pool comes up.
    """
    if getattr(app.state, "checkpointer_pool", None) is not None:
        return

    dsn = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    if not dsn:
        log.warning("checkpointer pool not opened: DATABASE_URL unset")
        app.state.checkpointer_pool = None
        app.state.checkpointer = None
        return

    pool = AsyncConnectionPool(
        conninfo=dsn,
        min_size=_POOL_MIN,
        max_size=_POOL_MAX,
        kwargs={"autocommit": True, "prepare_threshold": 0},
        open=False,
    )
    try:
        await pool.open(wait=True, timeout=10.0)
    except Exception:  # noqa: BLE001 — surface as 503, do not crash app startup
        log.exception("checkpointer pool failed to open")
        app.state.checkpointer_pool = None
        app.state.checkpointer = None
        return

    saver = AsyncPostgresSaver(pool)  # type: ignore[arg-type]
    app.state.checkpointer_pool = pool
    app.state.checkpointer = saver
    log.info(
        "checkpointer pool opened",
        min_size=_POOL_MIN,
        max_size=_POOL_MAX,
    )


async def close_checkpointer(app: FastAPI) -> None:
    pool = getattr(app.state, "checkpointer_pool", None)
    if pool is None:
        return
    try:
        await pool.close()
    except Exception:  # noqa: BLE001 — log + continue
        log.exception("checkpointer pool close failed")
    app.state.checkpointer_pool = None
    app.state.checkpointer = None


def get_checkpointer(app: FastAPI) -> AsyncPostgresSaver | None:
    """Return the lifespan saver, or None if it failed to open."""
    return getattr(app.state, "checkpointer", None)


__all__ = [
    "close_checkpointer",
    "get_checkpointer",
    "open_checkpointer",
]
