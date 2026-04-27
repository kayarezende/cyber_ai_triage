"""Smoke that `build_mcp()` registers the wk-2 tool surface.

No Splunk, no MCP transport, no LLM — purely confirms the FastMCP server
exposes the tools the agent will see at JSONSchema-list time.
"""

from __future__ import annotations

import pytest

from sentient_mcp_splunk.server import build_mcp


@pytest.mark.asyncio
async def test_siem_query_registered() -> None:
    mcp = build_mcp()
    tools = await mcp.list_tools()
    by_name = {t.name: t for t in tools}
    assert "siem_query" in by_name

    schema = by_name["siem_query"].inputSchema
    props = schema.get("properties", {})
    assert {"spl", "earliest", "latest", "max_count", "timeout_seconds"} <= set(props)
    assert props["spl"]["type"] == "string"
    assert props["max_count"]["type"] == "integer"


@pytest.mark.asyncio
async def test_siem_get_notable_registered() -> None:
    mcp = build_mcp()
    tools = await mcp.list_tools()
    by_name = {t.name: t for t in tools}
    assert "siem_get_notable" in by_name
    schema = by_name["siem_get_notable"].inputSchema
    assert "notable_id" in schema.get("properties", {})


@pytest.mark.asyncio
async def test_tool_count_matches_wk2_scope() -> None:
    """Wk-2 ships exactly `siem_query` + `siem_get_notable`.

    Fails loud if anyone adds a tool out of plan order. Wk-6 grows the
    surface (`siem_get_entity_history`, `siem_process_tree`,
    `siem_lookup_ioc`); wk-8 adds the writeback tools. Bump this set then.
    """
    mcp = build_mcp()
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    expected: set[str] = {"siem_query", "siem_get_notable"}
    assert names == expected, f"unexpected tool surface: {names - expected}"
