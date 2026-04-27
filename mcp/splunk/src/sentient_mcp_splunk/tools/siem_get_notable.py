"""`siem_get_notable` — fetch a Splunk notable event by ID.

Plain Splunk Enterprise has no `index=notable` (that's a Splunk Enterprise
Security artifact). The tool detects absence and returns `degraded=true` so
the agent can skip the inline `notable_update` writeback path while still
shipping the verdict via HEC. See ADR-0018.

The notable_id input is validated against `NOTABLE_ID_PATTERN`; we ALSO
double-quote it in the SPL string. Defence in depth — a future schema change
that loosens the regex shouldn't open SPL injection.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from mcp.server.fastmcp import FastMCP
from splunklib import results as splunk_results
from splunklib.binding import AuthenticationError, HTTPError

from sentient_common.logging import get_logger
from sentient_mcp_splunk.errors import (
    SiemToolError,
    auth_failure,
    internal,
    search_timeout,
    splunk_http_error,
)
from sentient_mcp_splunk.schemas.siem_get_notable import (
    SiemGetNotableInput,
    SiemGetNotableOutput,
)
from sentient_mcp_splunk.schemas.siem_query import SiemEvent
from sentient_mcp_splunk.settings import SplunkSettings
from sentient_mcp_splunk.splunk_client import SplunkClientFactory
from sentient_mcp_splunk.tools.siem_query import _dict_to_event

log = get_logger(__name__)

TOOL_DESCRIPTION = (
    "Fetch a SIEM notable event by ID. On Splunk Enterprise Security tenants "
    "this resolves via `index=notable`; on plain Splunk Enterprise the tool "
    "returns `degraded=true` (no notable index) so the agent can skip inline "
    "notable_update writeback and ship the verdict via HEC only."
)

_NOTABLE_INDEX_NAME = "notable"
_DEGRADED_NOTES = (
    "no `index=notable` on this Splunk instance — verdict workflow is "
    "hec_only (ADR-0018). Verdict still posts to triage_verdicts."
)
_LOOKUP_TIMEOUT_SECONDS = 15

# Process-wide cache for the `notable` index presence probe. Service.indexes
# is a remote REST collection; without this cache every `siem_get_notable`
# call on a plain-Splunk tenant would burn an extra HTTP round-trip just to
# learn the index still doesn't exist.
_notable_index_cache_lock = threading.Lock()
_notable_index_present: bool | None = None


def _reset_notable_index_cache() -> None:
    """Drop the cached probe result. Tests use this to exercise both branches."""
    global _notable_index_present
    with _notable_index_cache_lock:
        _notable_index_present = None


class _NotableIndexAbsentError(Exception):
    """Internal sentinel — caught by the handler and turned into a degraded
    response. NOT an `SiemToolError` because absence is structurally OK."""


def _has_notable_index(service: Any) -> bool:
    global _notable_index_present
    with _notable_index_cache_lock:
        if _notable_index_present is not None:
            return _notable_index_present
    try:
        _ = service.indexes[_NOTABLE_INDEX_NAME]
    except KeyError:
        present = False
    except (AuthenticationError, HTTPError):
        # Don't cache transient errors — let the next call retry the probe.
        raise
    else:
        present = True
    with _notable_index_cache_lock:
        _notable_index_present = present
    return present


def _run_lookup_sync(notable_id: str) -> Any:
    settings = SplunkSettings()  # type: ignore[call-arg]
    service = SplunkClientFactory.get(settings)
    if not _has_notable_index(service):
        raise _NotableIndexAbsentError
    safe = notable_id.replace('"', "")
    spl = f'search index=notable event_id="{safe}" | head 1'
    return service.jobs.oneshot(
        spl,
        earliest_time="-100y",
        latest_time="now",
        count=1,
        output_mode="json",
    )


async def siem_get_notable(input_: SiemGetNotableInput) -> SiemGetNotableOutput:
    started = time.perf_counter()
    log.info("siem_get_notable starting", notable_id=input_.notable_id)

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(_run_lookup_sync, input_.notable_id),
            timeout=_LOOKUP_TIMEOUT_SECONDS,
        )
    except _NotableIndexAbsentError:
        log.info(
            "siem_get_notable degraded",
            notable_id=input_.notable_id,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return SiemGetNotableOutput(
            notable_id=input_.notable_id,
            found=False,
            degraded=True,
            event=None,
            notes=_DEGRADED_NOTES,
        )
    except SiemToolError:
        # Already-mapped tool error — never re-wrap. Without this clause the
        # `except Exception` below would re-classify as `internal`.
        raise
    except TimeoutError as exc:
        raise search_timeout(_LOOKUP_TIMEOUT_SECONDS) from exc
    except AuthenticationError as exc:
        SplunkClientFactory.reset()
        _reset_notable_index_cache()
        raise auth_failure() from exc
    except HTTPError as exc:
        status = getattr(exc, "status", 500)
        raise splunk_http_error(int(status), str(exc)) from exc
    except Exception as exc:
        raise internal(f"unexpected splunk error: {exc}") from exc

    event: SiemEvent | None = None
    for item in splunk_results.JSONResultsReader(response):
        if isinstance(item, dict):
            event = _dict_to_event(item)
            break

    log.info(
        "siem_get_notable complete",
        notable_id=input_.notable_id,
        found=event is not None,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return SiemGetNotableOutput(
        notable_id=input_.notable_id,
        found=event is not None,
        degraded=False,
        event=event,
        notes=None,
    )


def register(mcp: FastMCP) -> None:
    """Register `siem_get_notable` on the FastMCP instance."""

    @mcp.tool(name="siem_get_notable", description=TOOL_DESCRIPTION)
    async def siem_get_notable_tool(notable_id: str) -> SiemGetNotableOutput:
        return await siem_get_notable(SiemGetNotableInput(notable_id=notable_id))
