"""`siem_query` — generic ad-hoc SPL search.

Wraps `service.jobs.oneshot(...)` from splunk-sdk: synchronous, time-bound,
returns parsed events. Suited for agent calls up to ~1000 events. Longer
searches will land via `service.jobs.create()` + polling in wk 6 (only when
the budget caps actually require it).

splunk-sdk is sync; we wrap the call in `asyncio.to_thread` and bound it with
`asyncio.wait_for(timeout=timeout_seconds)`. Caveat: cancelling the asyncio
future does NOT cancel the underlying Splunk job — the thread continues
running until Splunk returns or times out itself. Acceptable for wk 2;
explicit `job.cancel()` for true cancellation lands wk 6+.
"""

from __future__ import annotations

import asyncio
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
from sentient_mcp_splunk.schemas.siem_query import (
    SiemEvent,
    SiemQueryInput,
    SiemQueryOutput,
)
from sentient_mcp_splunk.settings import SplunkSettings
from sentient_mcp_splunk.splunk_client import SplunkClientFactory

log = get_logger(__name__)

TOOL_DESCRIPTION = (
    "Run an ad-hoc SPL search against the SIEM and return parsed events. "
    "`search` is auto-prepended when missing. Forbids side-effecting SPL "
    "(outputlookup, collect, sendalert, script, delete, rest method=POST). "
    "Truncates at `max_count` events; returned `truncated=true` signals more "
    "exist in Splunk."
)

# SPL commands that don't require `search` to be prepended (they're already
# generating commands that own the front of the pipeline).
GENERATING_COMMANDS: frozenset[str] = frozenset(
    {
        "search",
        "tstats",
        "metasearch",
        "datamodel",
        "metadata",
        "rest",
        "inputlookup",
        "from",
        "loadjob",
        "savedsearch",
        "mstats",
        "geomstats",
    }
)

CANONICAL_EVENT_FIELDS: frozenset[str] = frozenset(
    {"_raw", "_time", "sourcetype", "source", "host", "index"}
)


def normalize_spl(spl: str) -> str:
    """Prepend `search ` when the SPL doesn't start with a generating command.

    Splunk's REST endpoint requires an explicit search prefix for non-generators.
    The agent often emits `index=foo ...` shorthand which would 400 without the
    prefix. We normalize once here so the `spl_executed` we return is the
    actual string Splunk ran.
    """
    s = spl.strip()
    if s.startswith("|"):
        return s
    first = s.split(maxsplit=1)[0].lower()
    if first in GENERATING_COMMANDS:
        return s
    return f"search {s}"


def _dict_to_event(row: dict[str, Any]) -> SiemEvent:
    extras = {
        k: v
        for k, v in row.items()
        if k not in CANONICAL_EVENT_FIELDS and not k.startswith("_")
    }
    return SiemEvent(
        _raw=str(row.get("_raw", "")),
        _time=row.get("_time"),
        sourcetype=row.get("sourcetype"),
        source=row.get("source"),
        host=row.get("host"),
        index=row.get("index"),
        fields=extras,
    )


def _run_oneshot_sync(
    spl_executed: str,
    earliest: str,
    latest: str,
    max_count: int,
) -> Any:
    """Sync helper run inside `asyncio.to_thread`. Returns the response stream."""
    settings = SplunkSettings()  # type: ignore[call-arg]
    service = SplunkClientFactory.get(settings)
    return service.jobs.oneshot(
        spl_executed,
        earliest_time=earliest,
        latest_time=latest,
        count=max_count,
        output_mode="json",
    )


async def siem_query(input_: SiemQueryInput) -> SiemQueryOutput:
    """Run an ad-hoc SPL search and return parsed events."""
    spl_executed = normalize_spl(input_.spl)
    started = time.perf_counter()
    log.info(
        "siem_query starting",
        spl_executed=spl_executed,
        earliest=input_.earliest,
        latest=input_.latest,
        max_count=input_.max_count,
    )

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                _run_oneshot_sync,
                spl_executed,
                input_.earliest,
                input_.latest,
                input_.max_count,
            ),
            timeout=input_.timeout_seconds,
        )
    except SiemToolError:
        # Already-mapped — never re-wrap as `internal`.
        raise
    except TimeoutError as exc:
        raise search_timeout(input_.timeout_seconds) from exc
    except AuthenticationError as exc:
        SplunkClientFactory.reset()
        raise auth_failure() from exc
    except HTTPError as exc:
        status = getattr(exc, "status", 500)
        raise splunk_http_error(int(status), str(exc)) from exc
    except Exception as exc:
        raise internal(f"unexpected splunk error: {exc}") from exc

    events: list[SiemEvent] = []
    for item in splunk_results.JSONResultsReader(response):
        if isinstance(item, dict):
            events.append(_dict_to_event(item))
        # Non-dict items are messages (warnings/info); drop silently.

    duration_ms = int((time.perf_counter() - started) * 1000)
    truncated = len(events) >= input_.max_count
    log.info(
        "siem_query complete",
        event_count=len(events),
        truncated=truncated,
        duration_ms=duration_ms,
    )
    return SiemQueryOutput(
        events=events,
        truncated=truncated,
        duration_ms=duration_ms,
        spl_executed=spl_executed,
    )


def register(mcp: FastMCP) -> None:
    """Register `siem_query` on the FastMCP instance.

    Tool args are explicit primitives (not the SiemQueryInput model directly)
    because FastMCP serialises each parameter into the JSONSchema the agent
    sees — the LLM gets cleaner doc when fields are flat. Pydantic validation
    still runs because we construct `SiemQueryInput` inside the handler.
    """

    @mcp.tool(name="siem_query", description=TOOL_DESCRIPTION)
    async def siem_query_tool(
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_count: int = 100,
        timeout_seconds: int = 30,
    ) -> SiemQueryOutput:
        return await siem_query(
            SiemQueryInput(
                spl=spl,
                earliest=earliest,
                latest=latest,
                max_count=max_count,
                timeout_seconds=timeout_seconds,
            )
        )
