"""`siem_notable_update` — attach a verdict comment to a Splunk ES notable.

Splunk ES only. On plain Splunk Enterprise (no `index=notable`) the tool
returns `degraded=true` so the orchestrator can fall back to HEC-only
writeback (per ADR-0018).

Splunk REST: `service.post('notable_update', notable_id=..., comment=...,
status=..., urgency=...)`. The kwargs become a form-encoded body via
splunk-sdk. Wrapped in `asyncio.to_thread` + `asyncio.wait_for` for the
async + timeout shape this server uses elsewhere.

Re-uses the wk-2 `_has_notable_index` cache from `siem_get_notable` — both
tools probe the same `index=notable` REST endpoint, so caching once at the
process level is sufficient and saves a round-trip per call on plain Splunk.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from mcp.server.fastmcp import FastMCP
from splunklib.binding import AuthenticationError, HTTPError

from sentient_common.logging import get_logger
from sentient_mcp_splunk.errors import (
    SiemToolError,
    auth_failure,
    internal,
    search_timeout,
    splunk_http_error,
)
from sentient_mcp_splunk.schemas.siem_notable_update import (
    SiemNotableUpdateInput,
    SiemNotableUpdateOutput,
)
from sentient_mcp_splunk.settings import SplunkSettings
from sentient_mcp_splunk.splunk_client import SplunkClientFactory
from sentient_mcp_splunk.tools.siem_get_notable import (
    _has_notable_index,
    _NotableIndexAbsentError,
    _reset_notable_index_cache,
)

log = get_logger(__name__)

TOOL_DESCRIPTION = (
    "Update a Splunk Enterprise Security notable event with an analyst-"
    "visible comment + optional status / urgency override. Splunk ES only. "
    "Returns `degraded=true` on plain Splunk Enterprise — caller should "
    "still post the verdict via `siem_hec_post`. Per ADR-0018."
)

_UPDATE_TIMEOUT_SECONDS = 15
_NOTABLE_UPDATE_PATH = "notable_update"


def _run_update_sync(
    notable_id: str,
    comment: str,
    status: str | None,
    urgency: str | None,
) -> dict[str, Any]:
    settings = SplunkSettings()  # type: ignore[call-arg]
    service = SplunkClientFactory.get(settings)
    if not _has_notable_index(service):
        raise _NotableIndexAbsentError
    kwargs: dict[str, Any] = {
        "notable_id": notable_id,
        "comment": comment,
    }
    if status is not None:
        kwargs["status"] = status
    if urgency is not None:
        kwargs["urgency"] = urgency
    response = service.post(_NOTABLE_UPDATE_PATH, **kwargs)
    body_bytes = response.body.read() if hasattr(response.body, "read") else b""
    body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    return {
        "status": int(getattr(response, "status", 0) or 0),
        "body": body_text[:2048],
    }


_DEGRADED_NOTES = (
    "no `index=notable` on this Splunk instance — siem_notable_update is a "
    "no-op (ADR-0018). Verdict still posts via siem_hec_post."
)


async def siem_notable_update(
    input_: SiemNotableUpdateInput,
) -> SiemNotableUpdateOutput:
    started = time.perf_counter()
    log.info(
        "siem_notable_update starting",
        notable_id=input_.notable_id,
        has_status=input_.status is not None,
        has_urgency=input_.urgency is not None,
    )

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                _run_update_sync,
                input_.notable_id,
                input_.comment,
                input_.status,
                input_.urgency,
            ),
            timeout=_UPDATE_TIMEOUT_SECONDS,
        )
    except _NotableIndexAbsentError:
        log.info(
            "siem_notable_update degraded",
            notable_id=input_.notable_id,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return SiemNotableUpdateOutput(
            notable_id=input_.notable_id,
            success=False,
            degraded=True,
            splunk_response=None,
            notes=_DEGRADED_NOTES,
        )
    except SiemToolError:
        # Already-mapped tool error — never re-wrap.
        raise
    except TimeoutError as exc:
        raise search_timeout(_UPDATE_TIMEOUT_SECONDS) from exc
    except AuthenticationError as exc:
        SplunkClientFactory.reset()
        _reset_notable_index_cache()
        raise auth_failure() from exc
    except HTTPError as exc:
        status = int(getattr(exc, "status", 500) or 500)
        raise splunk_http_error(status, str(exc)) from exc
    except Exception as exc:
        raise internal(f"unexpected splunk error: {exc}") from exc

    http_status = int(response.get("status", 0))
    success = 200 <= http_status < 300
    log.info(
        "siem_notable_update complete",
        notable_id=input_.notable_id,
        http_status=http_status,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return SiemNotableUpdateOutput(
        notable_id=input_.notable_id,
        success=success,
        degraded=False,
        splunk_response=response,
        notes=None if success else f"non-2xx HTTP status: {http_status}",
    )


def register(mcp: FastMCP) -> None:
    """Register `siem_notable_update` on the FastMCP instance."""

    @mcp.tool(name="siem_notable_update", description=TOOL_DESCRIPTION)
    async def siem_notable_update_tool(
        notable_id: str,
        comment: str,
        status: str | None = None,
        urgency: str | None = None,
    ) -> SiemNotableUpdateOutput:
        return await siem_notable_update(
            SiemNotableUpdateInput(
                notable_id=notable_id,
                comment=comment,
                status=status,  # type: ignore[arg-type]
                urgency=urgency,  # type: ignore[arg-type]
            )
        )
