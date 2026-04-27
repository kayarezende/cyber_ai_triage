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
async def test_tool_count_matches_wk8_scope() -> None:
    """Wk-2 shipped `siem_query` + `siem_get_notable`. Wk-8 added the
    writeback surface (`siem_notable_update` + `siem_hec_post`).

    Fails loud if anyone adds a tool out of plan order. Wk-6 expansion (e.g.
    `siem_get_entity_history`, `siem_process_tree`, `siem_lookup_ioc`) was
    deferred — bump this set when those land.
    """
    mcp = build_mcp()
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    expected: set[str] = {
        "siem_query",
        "siem_get_notable",
        "siem_notable_update",
        "siem_hec_post",
    }
    assert names == expected, f"unexpected tool surface: {names ^ expected}"


@pytest.mark.asyncio
async def test_siem_notable_update_registered() -> None:
    mcp = build_mcp()
    tools = await mcp.list_tools()
    by_name = {t.name: t for t in tools}
    assert "siem_notable_update" in by_name
    schema = by_name["siem_notable_update"].inputSchema
    props = schema.get("properties", {})
    assert "notable_id" in props
    assert "comment" in props


@pytest.mark.asyncio
async def test_siem_hec_post_registered() -> None:
    mcp = build_mcp()
    tools = await mcp.list_tools()
    by_name = {t.name: t for t in tools}
    assert "siem_hec_post" in by_name
    schema = by_name["siem_hec_post"].inputSchema
    props = schema.get("properties", {})
    assert "event" in props
