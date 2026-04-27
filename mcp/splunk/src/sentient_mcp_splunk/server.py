"""FastMCP server factory.

Tool registration happens here so `main.py` is free to wire transport + the
`/health` Starlette route without growing tool-specific imports. Wk-2 ships
empty (Day 2 transport-gate); `siem_query` lands Day 3, `siem_get_notable`
Day 4.

Wk-10: `MCP_ALLOWED_HOSTS` env var passes the docker-network service
hostname (`mcp-splunk:8080`) through FastMCP's DNS-rebinding guard.
Without it the streamable_http transport rejects in-cluster client
requests with 421 Misdirected Request because the default allowlist is
limited to localhost/127.0.0.1 only.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from sentient_mcp_splunk.tools import (
    siem_get_notable,
    siem_hec_post,
    siem_notable_update,
    siem_query,
)


def _build_transport_security() -> TransportSecuritySettings:
    """Resolve `MCP_ALLOWED_HOSTS` (comma-separated) into a settings object.

    Defaults cover the in-cluster service hostname + the host-network ports
    used for `evals/run_eval.py` and the wk-2 verify smoke. Add any extra
    deployment-specific hostnames via the env var; never disable rebinding
    protection in prod.
    """
    raw = os.environ.get("MCP_ALLOWED_HOSTS", "")
    extras = [h.strip() for h in raw.split(",") if h.strip()]
    allowed = [
        "localhost:8080",
        "127.0.0.1:8080",
        "mcp-splunk:8080",
        *extras,
    ]
    return TransportSecuritySettings(allowed_hosts=allowed)


def build_mcp() -> FastMCP:
    """Construct + return the FastMCP instance with all siem_* tools registered.

    Tool registration follows `tasks/todo.md`. Each tool module exports a
    `register(mcp)` function so this file stays a one-screen surface for
    "what tools does the agent see".

    Wk-2 shipped `siem_query` + `siem_get_notable`. Wk-8 adds the writeback
    surface: `siem_notable_update` (ES-only, degraded on plain Splunk) +
    `siem_hec_post` (always-available HEC POST to `triage_verdicts`).
    """
    mcp = FastMCP(
        "sentient-siem-splunk",
        transport_security=_build_transport_security(),
    )
    siem_query.register(mcp)
    siem_get_notable.register(mcp)
    siem_notable_update.register(mcp)
    siem_hec_post.register(mcp)
    return mcp
