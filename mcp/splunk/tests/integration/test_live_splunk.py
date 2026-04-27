"""Live Splunk integration tests — founder-box only.

Requires:

- `SPLUNK_HOST`, `SPLUNK_TOKEN` etc. set to a reachable Splunk instance.
- BOTS v3 loaded into `index=botsv3` (per `docs/splunk-setup.md` §6).
- `uv run pytest -m integration mcp/splunk/tests/integration` to run.

Default `pytest` invocations skip via root `addopts = "-m 'not integration'"`.

These tests are golden-style: syrupy snapshots fingerprint the *shape* of
real Splunk responses (event field names, OCSF-relevant key presence) so
schema drift in Splunk's stream:http / WinEventLog sourcetypes shows up as
a snapshot diff. They do NOT snapshot raw event content (volatile across
indexings).
"""

from __future__ import annotations

import os

import pytest

from sentient_mcp_splunk.schemas.siem_query import SiemQueryInput
from sentient_mcp_splunk.tools.siem_query import siem_query

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def _live_splunk_env() -> None:
    """Skip integration test when env points at the placeholder."""
    host = os.environ.get("SPLUNK_HOST", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    if not host or token.startswith("CHANGEME_") or host == "splunk.internal":
        pytest.skip(
            "live Splunk env missing — set SPLUNK_HOST + SPLUNK_TOKEN to "
            "a reachable Splunk box with BOTS v3 loaded"
        )


async def test_internal_basic_query() -> None:
    """Smoke against `index=_internal` — always present, recent data."""
    out = await siem_query(
        SiemQueryInput(
            spl="index=_internal | head 5",
            earliest="-1h",
            latest="now",
            max_count=5,
        )
    )
    assert len(out.events) >= 1, "expected ≥1 _internal event in last hour"
    assert out.duration_ms > 0
    assert out.spl_executed.startswith("search ") or out.spl_executed.startswith("|")
    # Every event has a non-empty raw payload.
    assert all(ev.raw for ev in out.events)


async def test_botsv3_login_failures_4625(snapshot) -> None:  # type: ignore[no-untyped-def]
    """BOTS v3-dependent — skips if the dataset isn't loaded."""
    # Splunk 10.0.2 rejects `-100y`; use the BOTS v3 date window directly.
    out = await siem_query(
        SiemQueryInput(
            spl="index=botsv3 sourcetype=WinEventLog:Security EventCode=4625 | head 3",
            earliest="2018-08-01T00:00:00",
            latest="2018-09-30T00:00:00",
            max_count=3,
        )
    )
    if not out.events:
        pytest.skip(
            "no BOTS v3 4625 events — load BOTS v3 into `index=botsv3` per "
            "`docs/splunk-setup.md` §6, or this test stays skipped"
        )
    fingerprint = {
        "sourcetype": out.events[0].sourcetype,
        "has_host": out.events[0].host is not None,
        "extracted_field_keys": sorted(out.events[0].fields.keys()),
    }
    assert fingerprint == snapshot


async def test_botsv3_dns_stream(snapshot) -> None:  # type: ignore[no-untyped-def]
    """BOTS v3-dependent — skips if the dataset isn't loaded."""
    out = await siem_query(
        SiemQueryInput(
            spl="index=botsv3 sourcetype=stream:dns | head 3",
            earliest="2018-08-01T00:00:00",
            latest="2018-09-30T00:00:00",
            max_count=3,
        )
    )
    if not out.events:
        pytest.skip("no BOTS v3 stream:dns events — load BOTS v3")
    fingerprint = {
        "sourcetype": out.events[0].sourcetype,
        "extracted_field_keys": sorted(out.events[0].fields.keys()),
    }
    assert fingerprint == snapshot
