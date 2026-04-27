"""ASGI entrypoint for the Splunk MCP server.

Co-locates the MCP `streamable_http` endpoint (mounted by FastMCP at `/mcp`)
with the `/health` route the docker-compose healthcheck probes. Both are
served from the same Starlette app via FastMCP's `custom_route` decorator —
no parent FastAPI wrapper needed.

Transport choice rationale: ADR-0019.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from sentient_common.logging import configure_logging, get_logger
from sentient_mcp_splunk.server import build_mcp

configure_logging(service="mcp-splunk")
log = get_logger(__name__)

mcp = build_mcp()


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mcp-splunk"})


# uvicorn target — `sentient_mcp_splunk.main:app`. Same path the Dockerfile
# CMD + docker-compose.override.yml --reload command point at, so the
# transport flip from FastAPI → FastMCP is invisible to the runtime config.
app = mcp.streamable_http_app()
log.info("mcp-splunk ready", transport="streamable_http", health_path="/health")
