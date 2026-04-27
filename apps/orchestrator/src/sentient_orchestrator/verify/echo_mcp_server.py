"""Trivial in-process MCP server for the wk-2 verify harness.

Exposes a single `echo(msg) -> str` tool over stdio. Spawned as a subprocess by
`MultiServerMCPClient` so the framework-stack verification can run without
depending on the real `mcp/splunk` server being implemented yet.

Run: `python -m sentient_orchestrator.verify.echo_mcp_server`
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("verify-echo")


@mcp.tool()
def echo(msg: str) -> str:
    """Echo the input message back, prefixed."""
    return f"echoed: {msg}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
