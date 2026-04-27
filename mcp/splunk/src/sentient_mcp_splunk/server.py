"""FastMCP server factory.

Tool registration happens here so `main.py` is free to wire transport + the
`/health` Starlette route without growing tool-specific imports. Wk-2 ships
empty (Day 2 transport-gate); `siem_query` lands Day 3, `siem_get_notable`
Day 4.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from sentient_mcp_splunk.tools import (
    siem_get_notable,
    siem_hec_post,
    siem_notable_update,
    siem_query,
)


def build_mcp() -> FastMCP:
    """Construct + return the FastMCP instance with all siem_* tools registered.

    Tool registration follows `tasks/todo.md`. Each tool module exports a
    `register(mcp)` function so this file stays a one-screen surface for
    "what tools does the agent see".

    Wk-2 shipped `siem_query` + `siem_get_notable`. Wk-8 adds the writeback
    surface: `siem_notable_update` (ES-only, degraded on plain Splunk) +
    `siem_hec_post` (always-available HEC POST to `triage_verdicts`).
    """
    mcp = FastMCP("sentient-siem-splunk")
    siem_query.register(mcp)
    siem_get_notable.register(mcp)
    siem_notable_update.register(mcp)
    siem_hec_post.register(mcp)
    return mcp
