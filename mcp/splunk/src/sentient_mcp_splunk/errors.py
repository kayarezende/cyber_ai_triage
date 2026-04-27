"""MCP-level error taxonomy for siem_* tools.

JSON-RPC error codes per the MCP spec:
    -32602  Invalid params (Pydantic input validation; FastMCP raises this
            automatically when input doesn't match the typed handler).
    -32000  Server error, app-defined. We use `data.kind` to discriminate:
              - "auth_failure"     splunk-sdk AuthenticationError
              - "search_timeout"   asyncio.wait_for timed out
              - "splunk_4xx"       splunklib.binding.HTTPError 4xx
              - "splunk_5xx"       splunklib.binding.HTTPError 5xx
              - "internal"         catch-all

Empty result for `siem_query` is NOT an error — it returns `events=[]`. The
agent treats "no results" as a valid investigative observation.

Audit boundary: the orchestrator wraps every tool call in an `audit_log` row
(wk-6). The MCP server itself does not write to Postgres — it stays free of
DB dependencies and runs even when Postgres is down (the orchestrator buffers
or marks the investigation inconclusive).
"""

from __future__ import annotations

from typing import Any

from mcp import McpError
from mcp.types import INTERNAL_ERROR, ErrorData


class SiemToolError(McpError):
    """Wrap arbitrary tool failures with structured `data.kind`."""

    def __init__(self, kind: str, message: str, **extra: Any) -> None:
        data: dict[str, Any] = {"kind": kind, **extra}
        super().__init__(error=ErrorData(code=INTERNAL_ERROR, message=message, data=data))
        self.kind = kind


def auth_failure(message: str = "splunk auth failed; rotate SPLUNK_TOKEN") -> SiemToolError:
    return SiemToolError(kind="auth_failure", message=message)


def search_timeout(timeout_seconds: int) -> SiemToolError:
    return SiemToolError(
        kind="search_timeout",
        message=f"search exceeded {timeout_seconds}s timeout",
        timeout_seconds=timeout_seconds,
    )


def splunk_http_error(status: int, message: str) -> SiemToolError:
    bucket = "splunk_4xx" if 400 <= status < 500 else "splunk_5xx"
    return SiemToolError(kind=bucket, message=message, status=status)


def internal(message: str, **extra: Any) -> SiemToolError:
    return SiemToolError(kind="internal", message=message, **extra)
