"""MCP client factory for the investigation graph.

`MultiServerMCPClient` from `langchain-mcp-adapters` resolves the streamable_http
transport (ADR-0019) against the in-cluster MCP Splunk server. The client
returns LangChain `BaseTool` instances; the investigation graph dispatches
them manually rather than using `ToolNode`, so we treat them as plain async
callables.

Lifecycle: open `async with build_mcp_client() as mcp:` once per investigation,
call `await mcp.get_tools()` once at graph start, then keep the client alive
across the entire `graph.ainvoke` so streamable_http sessions don't churn.
"""

from __future__ import annotations

import os

from langchain_mcp_adapters.client import MultiServerMCPClient

#: Env var name. Compose sets this on the orchestrator + worker services.
MCP_SPLUNK_URL_ENV = "MCP_SPLUNK_URL"


def build_mcp_client() -> MultiServerMCPClient:
    """Construct a single-server MCP client for the Splunk MCP backend.

    Raises `RuntimeError` if `MCP_SPLUNK_URL` is unset; this is a deployment
    error, not a runtime failure to fall back from.
    """
    url = os.environ.get(MCP_SPLUNK_URL_ENV)
    if not url:
        msg = f"{MCP_SPLUNK_URL_ENV} not configured"
        raise RuntimeError(msg)
    return MultiServerMCPClient(
        {
            "splunk": {
                "transport": "streamable_http",
                "url": url,
            }
        }
    )


__all__ = ["MCP_SPLUNK_URL_ENV", "build_mcp_client"]
