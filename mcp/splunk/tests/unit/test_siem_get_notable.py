"""Unit tests for `siem_get_notable` — schemas + handler with mocked Splunk."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from sentient_mcp_splunk.errors import SiemToolError
from sentient_mcp_splunk.schemas.siem_get_notable import (
    SiemGetNotableInput,
    SiemGetNotableOutput,
)
from sentient_mcp_splunk.tools.siem_get_notable import siem_get_notable


class TestSiemGetNotableInput:
    @pytest.mark.parametrize("nid", ["abc123", "evt-001", "host:port@01", "name.with.dots"])
    def test_valid_ids(self, nid: str) -> None:
        m = SiemGetNotableInput(notable_id=nid)
        assert m.notable_id == nid

    @pytest.mark.parametrize(
        "nid",
        [
            "",  # empty
            'notable" OR 1=1',  # SPL-injection attempt
            "id with spaces",
            "id;DROP",
            "x" * 257,  # over max
        ],
    )
    def test_rejected_ids(self, nid: str) -> None:
        with pytest.raises(ValidationError):
            SiemGetNotableInput(notable_id=nid)


@pytest.fixture(autouse=True)
def _reset_notable_cache() -> None:
    """Ensure each test starts with a fresh probe cache."""
    from sentient_mcp_splunk.tools.siem_get_notable import _reset_notable_index_cache

    _reset_notable_index_cache()


@pytest.mark.asyncio
class TestSiemGetNotableHandler:
    async def test_degraded_when_no_notable_index(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_get_notable as mod

        def fake_run(_id: str) -> object:
            raise mod._NotableIndexAbsentError

        monkeypatch.setattr(mod, "_run_lookup_sync", fake_run)
        out = await siem_get_notable(SiemGetNotableInput(notable_id="evt-1"))
        assert isinstance(out, SiemGetNotableOutput)
        assert out.degraded is True
        assert out.found is False
        assert out.event is None
        assert out.notes is not None
        assert "hec_only" in out.notes

    async def test_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sentient_mcp_splunk.tools import siem_get_notable as mod

        rows = [
            {
                "_raw": "notable raw",
                "_time": "2018-08-20T11:34:13.000-07:00",
                "sourcetype": "stash",
                "host": "ds-01",
                "index": "notable",
                "event_id": "evt-1",
                "src_ip": "10.0.0.42",
            }
        ]

        def fake_run(_id: str) -> object:
            return rows  # JSONResultsReader stub iterates this directly.

        def fake_reader(rows_arg: object) -> object:
            return iter(rows_arg)  # type: ignore[arg-type]

        monkeypatch.setattr(mod, "_run_lookup_sync", fake_run)
        monkeypatch.setattr(mod.splunk_results, "JSONResultsReader", fake_reader)

        out = await siem_get_notable(SiemGetNotableInput(notable_id="evt-1"))
        assert out.degraded is False
        assert out.found is True
        assert out.event is not None
        assert out.event.raw == "notable raw"
        assert out.event.fields["event_id"] == "evt-1"

    async def test_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sentient_mcp_splunk.tools import siem_get_notable as mod

        def fake_run(_id: str) -> object:
            return []

        def fake_reader(rows_arg: object) -> object:
            return iter(rows_arg)  # type: ignore[arg-type]

        monkeypatch.setattr(mod, "_run_lookup_sync", fake_run)
        monkeypatch.setattr(mod.splunk_results, "JSONResultsReader", fake_reader)

        out = await siem_get_notable(SiemGetNotableInput(notable_id="missing"))
        assert out.degraded is False
        assert out.found is False
        assert out.event is None

    async def test_auth_failure_maps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        from splunklib.binding import AuthenticationError, HTTPError

        from sentient_mcp_splunk.tools import siem_get_notable as mod

        class _R:
            def __init__(self, status: int) -> None:
                self.status = status
                self.reason = "x"
                self.headers: list[tuple[str, str]] = []
                self.body = io.BytesIO(b"x")

        cause = HTTPError(_R(401), "401")

        def boom(*_a: Any, **_k: Any) -> object:
            raise AuthenticationError("bad token", cause)

        monkeypatch.setattr(mod, "_run_lookup_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_get_notable(SiemGetNotableInput(notable_id="evt-1"))
        assert exc.value.kind == "auth_failure"

    async def test_index_probe_is_cached(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`_has_notable_index` should consult Service.indexes at most once
        across multiple `siem_get_notable` calls (until cache reset)."""
        from sentient_mcp_splunk.tools import siem_get_notable as mod

        index_lookup_count = {"n": 0}

        class FakeIndexes:
            def __getitem__(self, name: str) -> object:
                index_lookup_count["n"] += 1
                raise KeyError(name)

        class FakeService:
            indexes = FakeIndexes()

        def fake_get(_settings: Any) -> Any:
            return FakeService()

        monkeypatch.setattr(mod.SplunkClientFactory, "get", staticmethod(fake_get))
        # Two consecutive calls — second should hit the cache, not the probe.
        await siem_get_notable(SiemGetNotableInput(notable_id="evt-1"))
        await siem_get_notable(SiemGetNotableInput(notable_id="evt-2"))
        assert index_lookup_count["n"] == 1

    async def test_double_quote_stripped_for_spl_safety(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Pydantic regex blocks `"` already. Belt-and-braces: confirm
        the SPL-builder also strips `"` if it ever slips through."""
        from sentient_mcp_splunk.tools.siem_get_notable import _run_lookup_sync

        captured: dict[str, str] = {}

        class FakeService:
            class FakeIndexes:
                def __getitem__(self, name: str) -> object:
                    return object()  # notable index "exists"

            indexes = FakeIndexes()

            class FakeJobs:
                def oneshot(self, spl: str, **_kw: Any) -> object:
                    captured["spl"] = spl
                    return iter([])

            jobs = FakeJobs()

        def fake_get(_settings: Any) -> Any:
            return FakeService()

        monkeypatch.setattr(
            "sentient_mcp_splunk.tools.siem_get_notable.SplunkClientFactory.get",
            staticmethod(fake_get),
        )
        _run_lookup_sync('evt"1')
        assert '"' in captured["spl"]  # the SPL itself uses outer quotes
        # The notable_id quotes were stripped before being interpolated:
        assert 'event_id="evt1"' in captured["spl"]
