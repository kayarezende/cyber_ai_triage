"""FastAPI entrypoint.

Wire-up only — real domain routers (incidents, investigations, admin) land in
subsequent weeks per tasks/todo.md.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentient_common.logging import configure_logging, get_logger

from sentient_api.middleware.auth import DevBypassAuthMiddleware
from sentient_api.routers import health

configure_logging(service="api")
log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    log.info("api ready")
    yield


app = FastAPI(title="Sentient Layer API", version="0.0.1", lifespan=_lifespan)
app.add_middleware(DevBypassAuthMiddleware)
app.include_router(health.router)
