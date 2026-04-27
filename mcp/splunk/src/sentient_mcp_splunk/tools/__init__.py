"""siem_* tool handlers, registered onto FastMCP via `server.build_mcp()`.

# AUDIT BOUNDARY — orchestrator-side, not MCP-side.
#
# Every tool call must land an `audit_log` row (ADR-0017) with `actor`,
# `action='tool_call'`, `details=JSONB` containing tool name + args + sha256
# of result payload. That logging happens in the **orchestrator** wrapper
# around `tool.ainvoke(...)` (wk 6), not here. Reasoning:
#   - Keeps `mcp/splunk` free of a Postgres dependency — the MCP server
#     can run even when the audit DB role is unavailable.
#   - Audit chain integrity stays under the orchestrator's tenant context
#     (RLS), where `current_setting('app.current_tenant')` is set.
"""
