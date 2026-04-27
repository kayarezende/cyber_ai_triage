"""Schema-only tests — no Splunk, no MCP server."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentient_mcp_splunk.schemas.siem_query import (
    FORBIDDEN_SPL_COMMANDS,
    SiemEvent,
    SiemQueryInput,
    SiemQueryOutput,
)


class TestSiemQueryInput:
    def test_minimal_required(self) -> None:
        m = SiemQueryInput(spl="index=botsv3 | head 1")
        assert m.spl == "index=botsv3 | head 1"
        assert m.earliest == "-24h"
        assert m.latest == "now"
        assert m.max_count == 100
        assert m.timeout_seconds == 30

    @pytest.mark.parametrize("max_count", [0, 1001, 5000])
    def test_max_count_bounds(self, max_count: int) -> None:
        with pytest.raises(ValidationError):
            SiemQueryInput(spl="index=foo", max_count=max_count)

    @pytest.mark.parametrize("timeout", [0, 121, 3600])
    def test_timeout_bounds(self, timeout: int) -> None:
        with pytest.raises(ValidationError):
            SiemQueryInput(spl="index=foo", timeout_seconds=timeout)

    def test_spl_min_length(self) -> None:
        with pytest.raises(ValidationError):
            SiemQueryInput(spl="")

    def test_spl_max_length(self) -> None:
        with pytest.raises(ValidationError):
            SiemQueryInput(spl="x" * 4097)

    @pytest.mark.parametrize(
        "spl",
        [
            # Standard forms.
            "index=foo | outputlookup naughty.csv",
            "index=foo | outputcsv blah",
            "index=foo | collect index=triage",
            "search foo | sendalert webhook",
            "| script python evil.py",
            "index=foo | delete",
            "| rest method=POST /services/foo",
            # Whitespace-padding variants — the regex must catch all of these.
            "index=foo |outputlookup tight",
            "index=foo |  outputlookup double-space",
            "index=foo |\toutputlookup tab",
            # Case variants.
            "index=foo | OutputLookup mixed",
            "index=foo | OUTPUTLOOKUP upper",
            # `rest` with method=POST in alternative positions.
            "| rest splunk_server=local /endpoint method=post",
            "| rest method=Post /a",
        ],
    )
    def test_forbidden_spl_rejected(self, spl: str) -> None:
        with pytest.raises(ValidationError) as exc:
            SiemQueryInput(spl=spl)
        assert "forbidden SPL command" in str(exc.value)

    @pytest.mark.parametrize(
        "spl",
        [
            # Looks similar but not actually a forbidden command.
            "index=foo | head 1",
            "index=foo | stats count by host",
            # Word that contains a forbidden command as substring — \b boundary
            # in the regex means we don't match these.
            "index=foo | eval x=outputlookuper",
            "index=foo | search outputcsvfile=ok",
            # `rest` without method=POST is currently allowed — wk-2 lets read
            # uses through. Keep this in the test to flag if/when we tighten.
            "| rest /services/server/info",
        ],
    )
    def test_safe_spl_passes(self, spl: str) -> None:
        SiemQueryInput(spl=spl)  # must not raise

    def test_forbidden_command_list_is_lowercase(self) -> None:
        # The regex is case-insensitive, but we keep the canonical list
        # lowercase so it's easy to scan.
        for cmd in FORBIDDEN_SPL_COMMANDS:
            assert cmd == cmd.lower(), cmd


class TestSiemEvent:
    def test_aliases_round_trip(self) -> None:
        ev = SiemEvent(
            _raw="this is a raw event",
            _time="2018-08-20T11:34:13.000-07:00",
            sourcetype="WinEventLog:Security",
            host="DC-01",
            index="botsv3",
            fields={"src_ip": "10.0.0.42", "EventCode": "4625"},
        )
        assert ev.raw == "this is a raw event"
        assert ev.time is not None
        assert ev.sourcetype == "WinEventLog:Security"
        assert ev.fields["src_ip"] == "10.0.0.42"

    def test_time_unparseable_swallowed(self) -> None:
        ev = SiemEvent(_raw="x", _time="N/A")
        assert ev.time is None

    def test_default_fields_empty(self) -> None:
        ev = SiemEvent(_raw="x")
        assert ev.fields == {}

    def test_populate_by_name(self) -> None:
        # The populate_by_name=True config means we can construct from either
        # field name or alias.
        ev = SiemEvent(raw="from-name", time=None)
        assert ev.raw == "from-name"


class TestSiemQueryOutput:
    def test_basic(self) -> None:
        out = SiemQueryOutput(
            events=[SiemEvent(_raw="x")],
            truncated=False,
            duration_ms=42,
            spl_executed="search index=foo",
        )
        assert len(out.events) == 1
        assert out.duration_ms == 42
