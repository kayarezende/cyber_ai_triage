"""FastAPI entrypoint.

Wires up domain routers + the lifespan-cached LangGraph checkpointer the
wk-9 replay endpoints depend on. The orchestrator stays out of this
process — only `libs/common` schemas + storage + audit helpers leak in.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentient_api.clients.checkpointer import (
    close_checkpointer,
    open_checkpointer,
)
from sentient_api.middleware.auth import DevBypassAuthMiddleware
from sentient_api.routers import (
    approvals,
    audit,
    health,
    incidents,
    investigations,
    replay,
)
from sentient_api.routers.admin import (
    budgets as admin_budgets,
)
from sentient_api.routers.admin import (
    hitl_policies as admin_hitl_policies,
)
from sentient_api.routers.admin import (
    llm_roles as admin_llm_roles,
)
from sentient_api.routers.admin import (
    splunk_creds as admin_splunk_creds,
)
from sentient_api.routers.admin import (
    users as admin_users,
)
from sentient_common.logging import configure_logging, get_logger

configure_logging(service="api")
log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    await open_checkpointer(app)
    log.info("api ready")
    try:
        yield
    finally:
        await close_checkpointer(app)


app = FastAPI(title="Sentient Layer API", version="0.0.1", lifespan=_lifespan)
app.add_middleware(DevBypassAuthMiddleware)
app.include_router(health.router)
app.include_router(incidents.router)
app.include_router(investigations.router)
app.include_router(approvals.router)
app.include_router(audit.router)
app.include_router(replay.router)
app.include_router(admin_llm_roles.router)
app.include_router(admin_hitl_policies.router)
app.include_router(admin_budgets.router)
app.include_router(admin_splunk_creds.router)
app.include_router(admin_users.router)
