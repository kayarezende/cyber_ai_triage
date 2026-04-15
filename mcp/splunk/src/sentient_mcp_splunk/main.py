"""MCP Splunk server — /health stub only.

TODO wk 2: replace with mcp.server exposing siem_query, siem_get_notable,
siem_get_entity_history, siem_process_tree, siem_lookup_ioc,
siem_notable_update, siem_hec_post. Transport choice (stdio vs SSE/HTTP)
revisited when real tools land.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentient_common.logging import configure_logging, get_logger

configure_logging(service="mcp-splunk")
log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    log.info("mcp-splunk stub ready", note="real MCP tools land wk 2")
    yield


app = FastAPI(title="Sentient Layer MCP Splunk (stub)", version="0.0.1", lifespan=_lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "mcp-splunk"}
