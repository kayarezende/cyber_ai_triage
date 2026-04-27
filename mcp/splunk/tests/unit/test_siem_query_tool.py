"""siem_query tool handler — mocked Splunk SDK.

Verifies the happy path, the truncation flag, error mapping for the four
exception classes the handler maps, and the SPL-prepending behaviour.
"""

from __future__ import annotations

import io
from typing import Any

import pytest
from splunklib.binding import AuthenticationError, HTTPError

from sentient_mcp_splunk.errors import SiemToolError
from sentient_mcp_splunk.schemas.siem_query import SiemQueryInput
from sentient_mcp_splunk.tools.siem_query import (
    GENERATING_COMMANDS,
    _dict_to_event,
    normalize_spl,
    siem_query,
)


class _FakeResponse:
    """Minimal stand-in for splunk-sdk's response object — `body` must be a
    stream because `HTTPError.__init__` calls `response.body.read()`."""

    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self.reason = f"status-{status}"
        self.headers: list[tuple[str, str]] = []
        self.body = io.BytesIO(body)


class TestNormalizeSPL:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("index=foo earliest=-1h", "search index=foo earliest=-1h"),
            ("foo bar baz", "search foo bar baz"),
            ("search index=foo | head 1", "search index=foo | head 1"),
            ("| inputlookup users", "| inputlookup users"),
            ("tstats count from datamodel=foo", "tstats count from datamodel=foo"),
        ],
    )
    def test_prepends_search_when_needed(self, raw: str, expected: str) -> None:
        assert normalize_spl(raw) == expected

    def test_generating_commands_set(self) -> None:
        # Sanity — the set should include the SPL commands we explicitly skip.
        assert "search" in GENERATING_COMMANDS
        assert "tstats" in GENERATING_COMMANDS
        assert "rest" in GENERATING_COMMANDS


class TestDictToEvent:
    def test_canonical_fields_split_from_extras(self) -> None:
        row = {
            "_raw": "raw event",
            "_time": "2018-08-20T11:34:13.000-07:00",
            "sourcetype": "WinEventLog:Security",
            "source": "WinEventLog:Security",
            "host": "DC-01",
            "index": "botsv3",
            "EventCode": "4625",
            "src_ip": "10.0.0.42",
            "_indextime": "ignored",
        }
        ev = _dict_to_event(row)
        assert ev.raw == "raw event"
        assert ev.sourcetype == "WinEventLog:Security"
        assert "EventCode" in ev.fields
        assert ev.fields["EventCode"] == "4625"
        # `_indextime` (underscore-prefixed) goes nowhere — it's a Splunk
        # internal field, neither canonical nor user-extracted.
        assert "_indextime" not in ev.fields


@pytest.mark.asyncio
class TestSiemQueryHandler:
    async def test_happy_path(self, fake_oneshot: Any) -> None:
        fake_oneshot(
            [
                {
                    "_raw": "row 1",
                    "_time": "2018-08-20T11:34:13.000-07:00",
                    "sourcetype": "stream:http",
                    "host": "h1",
                },
                {
                    "_raw": "row 2",
                    "_time": "2018-08-20T11:34:14.000-07:00",
                    "sourcetype": "stream:http",
                    "host": "h2",
                },
            ]
        )
        out = await siem_query(SiemQueryInput(spl="index=botsv3 | head 2"))
        assert len(out.events) == 2
        assert out.events[0].raw == "row 1"
        assert out.spl_executed.startswith("search ")
        assert out.duration_ms >= 0
        assert out.truncated is False

    async def test_truncation_flag(self, fake_oneshot: Any) -> None:
        fake_oneshot([{"_raw": f"row {i}"} for i in range(5)])
        out = await siem_query(SiemQueryInput(spl="index=botsv3", max_count=5))
        assert out.truncated is True

    async def test_no_results_is_not_an_error(self, fake_oneshot: Any) -> None:
        fake_oneshot([])
        out = await siem_query(SiemQueryInput(spl="index=botsv3 nothing"))
        assert out.events == []
        assert out.truncated is False

    async def test_messages_dropped(self, fake_oneshot: Any) -> None:
        # JSONResultsReader yields non-dict messages alongside dicts; we drop them.
        from splunklib import results as splunk_results

        msg = splunk_results.Message("WARN", "deprecated field")
        fake_oneshot([{"_raw": "row 1"}, msg, {"_raw": "row 2"}])
        out = await siem_query(SiemQueryInput(spl="index=botsv3"))
        assert len(out.events) == 2

    async def test_auth_failure_maps(
        self, fake_oneshot: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_query as siem_query_mod

        # AuthenticationError(message, cause) — `cause` must itself be an
        # HTTPError; splunk-sdk reads `.status`/etc. off it.
        cause = HTTPError(_FakeResponse(401, b"unauth"), "401")

        def boom(*_a: Any, **_k: Any) -> object:
            raise AuthenticationError("bad token", cause)

        monkeypatch.setattr(siem_query_mod, "_run_oneshot_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_query(SiemQueryInput(spl="index=foo"))
        assert exc.value.kind == "auth_failure"

    async def test_timeout_maps(
        self, fake_oneshot: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        from sentient_mcp_splunk.tools import siem_query as siem_query_mod

        async def slow(*_a: Any, **_k: Any) -> object:
            await asyncio.sleep(10)
            return []

        async def fake_to_thread(_fn: Any, *_a: Any, **_k: Any) -> object:
            return await slow()

        monkeypatch.setattr(siem_query_mod.asyncio, "to_thread", fake_to_thread)

        with pytest.raises(SiemToolError) as exc:
            await siem_query(SiemQueryInput(spl="index=foo", timeout_seconds=1))
        assert exc.value.kind == "search_timeout"

    async def test_http_4xx_maps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_query as siem_query_mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise HTTPError(_FakeResponse(403, b"forbidden"), "forbidden")

        monkeypatch.setattr(siem_query_mod, "_run_oneshot_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_query(SiemQueryInput(spl="index=foo"))
        assert exc.value.kind == "splunk_4xx"

    async def test_http_5xx_maps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_query as siem_query_mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise HTTPError(_FakeResponse(503, b"down"), "down")

        monkeypatch.setattr(siem_query_mod, "_run_oneshot_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_query(SiemQueryInput(spl="index=foo"))
        assert exc.value.kind == "splunk_5xx"

    async def test_unexpected_error_maps_to_internal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_query as siem_query_mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise RuntimeError("unexpected")

        monkeypatch.setattr(siem_query_mod, "_run_oneshot_sync", boom)

        with pytest.raises(SiemToolError) as exc:
            await siem_query(SiemQueryInput(spl="index=foo"))
        assert exc.value.kind == "internal"
