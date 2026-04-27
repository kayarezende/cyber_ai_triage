"""Streamable-HTTP transport smoke for the Splunk MCP server.

Exists to:

1. **Day 2 transport gate** — runs against the empty FastMCP server (no tools
   registered yet). Asserts `langchain-mcp-adapters` can speak
   `streamable_http` to FastMCP at all. If this fails, the wk-2 transport
   choice (ADR-0019) is wrong and we need to pivot before sinking days into
   tool implementations.
2. **Day 5 tools-loaded smoke** — re-run after `siem_query` + `siem_get_notable`
   are registered. Asserts the agent can list + invoke the real tools through
   the same transport path it'll use in wk 6.

Founder runs:

    # Day 2 (skeleton up, no tools)
    uv run python -m sentient_orchestrator.verify.splunk_smoke
    # → expects tool_count=0

    # Day 5 (tools registered)
    uv run python -m sentient_orchestrator.verify.splunk_smoke --invoke
    # → expects tool_count=2, runs siem_query against `index=_internal`
    #   (always present, no data dependency).
"""

from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StreamableHttpConnection

from sentient_common.logging import configure_logging, get_logger

DEFAULT_URL = os.environ.get("MCP_SPLUNK_URL", "http://localhost:8080/mcp")

configure_logging(service="orchestrator-verify")
log = get_logger(__name__)


def _connection(url: str) -> StreamableHttpConnection:
    return StreamableHttpConnection(transport="streamable_http", url=url)


async def _smoke(url: str, *, invoke: bool) -> dict[str, Any]:
    client = MultiServerMCPClient({"splunk": _connection(url)})
    tools = await client.get_tools()
    summary: dict[str, Any] = {
        "url": url,
        "tool_count": len(tools),
        "tool_names": [t.name for t in tools],
        "invocation": None,
    }
    log.info(
        "splunk mcp tools listed",
        url=url,
        tool_count=summary["tool_count"],
        tool_names=summary["tool_names"],
    )

    if invoke and tools:
        target = next((t for t in tools if t.name == "siem_query"), tools[0])
        # `index=_internal` is always present on every Splunk install + has
        # recent log data. Avoids depending on BOTS v3 (which the founder
        # may or may not have loaded) or any other data set.
        # Splunk 10.0.2 rejects `earliest=-100y` ("Invalid earliest_time"),
        # so we use a sensible recent window.
        result = await target.ainvoke(
            {
                "spl": "search index=_internal | head 5",
                "earliest": "-1h",
                "latest": "now",
                "max_count": 5,
            }
        )
        summary["invocation"] = {"tool": target.name, "result_type": type(result).__name__}
        log.info("splunk mcp tool invoked", tool=target.name)

    return summary


async def _run(url: str, *, invoke: bool) -> int:
    summary = await _smoke(url, invoke=invoke)
    log.info("splunk_smoke_complete", **summary)
    if invoke and summary["tool_count"] < 2:
        log.error(
            "splunk_smoke FAILED: expected >=2 tools when --invoke set",
            **summary,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL, help=f"MCP endpoint (default: {DEFAULT_URL})")
    parser.add_argument(
        "--invoke",
        action="store_true",
        help="Also invoke siem_query against BOTS v3 (Day 5 mode).",
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.url, invoke=args.invoke))


if __name__ == "__main__":
    raise SystemExit(main())
