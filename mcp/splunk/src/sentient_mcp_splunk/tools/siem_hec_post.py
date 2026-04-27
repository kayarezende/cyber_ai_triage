"""`siem_hec_post` — POST an OCSF Detection Finding to Splunk HEC.

Always available (HEC ships in plain Splunk Enterprise). Uses `httpx`
directly, NOT splunk-sdk — HEC has a different host / port / auth shape
than the management REST API.

The OCSF event payload comes from the orchestrator's writeback_node, which
runs `DetectionFinding.to_hec_dict()` over the verdict + Sentient extensions
and ships the result here.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from sentient_common.logging import get_logger
from sentient_mcp_splunk.errors import (
    SiemToolError,
    auth_failure,
    internal,
    search_timeout,
    splunk_http_error,
)
from sentient_mcp_splunk.schemas.siem_hec_post import (
    SiemHecPostInput,
    SiemHecPostOutput,
)
from sentient_mcp_splunk.settings import SplunkSettings

log = get_logger(__name__)

TOOL_DESCRIPTION = (
    "POST an OCSF Detection Finding event to Splunk HEC (default index "
    "`triage_verdicts`). Always available — works on plain Splunk Enterprise. "
    "Caller is responsible for shaping the event dict via "
    "`DetectionFinding.to_hec_dict()`."
)

_HEC_PATH = "/services/collector/event"
_HEC_TIMEOUT_SECONDS = 15.0


def _build_hec_url(settings: SplunkSettings) -> str:
    return f"https://{settings.splunk_hec_host}:{settings.splunk_hec_port}{_HEC_PATH}"


async def siem_hec_post(input_: SiemHecPostInput) -> SiemHecPostOutput:
    settings = SplunkSettings()  # type: ignore[call-arg]
    if not settings.splunk_hec_host or not settings.splunk_hec_token:
        raise internal(
            "HEC not configured: set SPLUNK_HEC_HOST + SPLUNK_HEC_TOKEN"
        )

    url = _build_hec_url(settings)
    headers = {
        "Authorization": f"Splunk {settings.splunk_hec_token}",
        "Content-Type": "application/json",
    }
    body: dict[str, Any] = {"event": input_.event}
    if input_.sourcetype:
        body["sourcetype"] = input_.sourcetype
    if input_.index:
        body["index"] = input_.index

    started = time.perf_counter()
    log.info(
        "siem_hec_post starting",
        index=input_.index,
        sourcetype=input_.sourcetype,
        host=settings.splunk_hec_host,
    )

    try:
        async with httpx.AsyncClient(
            verify=settings.splunk_verify_tls,
            timeout=_HEC_TIMEOUT_SECONDS,
        ) as client:
            resp = await client.post(url, json=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise search_timeout(int(_HEC_TIMEOUT_SECONDS)) from exc
    except httpx.HTTPError as exc:
        raise internal(f"HEC transport error: {exc!s}") from exc
    except SiemToolError:
        raise
    except Exception as exc:
        raise internal(f"unexpected HEC error: {exc!s}") from exc

    if resp.status_code == 401 or resp.status_code == 403:
        raise auth_failure(
            "HEC token rejected; rotate SPLUNK_HEC_TOKEN"
        )
    if resp.status_code >= 400:
        raise splunk_http_error(resp.status_code, resp.text[:500])

    duration_ms = int((time.perf_counter() - started) * 1000)
    log.info(
        "siem_hec_post complete",
        index=input_.index,
        status_code=resp.status_code,
        duration_ms=duration_ms,
    )
    return SiemHecPostOutput(
        success=True,
        status_code=resp.status_code,
        response_text=resp.text[:2048],
        notes=None,
    )


def register(mcp: FastMCP) -> None:
    """Register `siem_hec_post` on the FastMCP instance."""

    @mcp.tool(name="siem_hec_post", description=TOOL_DESCRIPTION)
    async def siem_hec_post_tool(
        event: dict[str, Any],
        sourcetype: str | None = "sentient:detection_finding",
        index: str | None = "triage_verdicts",
    ) -> SiemHecPostOutput:
        return await siem_hec_post(
            SiemHecPostInput(
                event=event,
                sourcetype=sourcetype,
                index=index,
            )
        )
