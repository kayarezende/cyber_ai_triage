"""Wk-8 unit tests for `siem_hec_post`.

Mocks `httpx.AsyncClient` via a small stub so we can assert request shape +
exercise each error mapping without a live HEC.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from sentient_mcp_splunk.errors import SiemToolError
from sentient_mcp_splunk.schemas.siem_hec_post import (
    SiemHecPostInput,
    SiemHecPostOutput,
)
from sentient_mcp_splunk.tools.siem_hec_post import siem_hec_post


@pytest.fixture
def hec_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_HOST", "splunk.local")
    monkeypatch.setenv("SPLUNK_TOKEN", "token")
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", "false")
    monkeypatch.setenv("SPLUNK_HEC_HOST", "hec.local")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "hec-token")


class TestSiemHecPostInput:
    def test_minimal_valid(self) -> None:
        m = SiemHecPostInput(event={"x": 1})
        assert m.event == {"x": 1}
        assert m.sourcetype == "sentient:detection_finding"
        assert m.index == "triage_verdicts"

    def test_index_and_sourcetype_overridable(self) -> None:
        m = SiemHecPostInput(event={"x": 1}, index="alt", sourcetype="other")
        assert m.index == "alt"
        assert m.sourcetype == "other"

    def test_extra_field_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            SiemHecPostInput(event={"x": 1}, foo="bar")  # type: ignore[call-arg]

    def test_empty_event_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SiemHecPostInput(event={})

    def test_long_sourcetype_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SiemHecPostInput(event={"x": 1}, sourcetype="x" * 129)


def _stub_client_factory(captured: dict[str, Any]) -> Any:
    """Return a class to monkeypatch `httpx.AsyncClient` with."""

    class _StubClient:
        def __init__(self, *_args: Any, verify: bool = True, **_kw: Any) -> None:
            captured["verify"] = verify

        async def __aenter__(self) -> _StubClient:
            return self

        async def __aexit__(self, *_a: Any) -> None:
            return None

        async def post(
            self,
            url: str,
            *,
            json: dict[str, Any],
            headers: dict[str, str],
        ) -> Any:
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return captured["response"]

    return _StubClient


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text


@pytest.mark.asyncio
class TestSiemHecPostHandler:
    async def test_request_shape(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        captured: dict[str, Any] = {"response": _Resp(200, '{"text":"ok"}')}
        monkeypatch.setattr(mod.httpx, "AsyncClient", _stub_client_factory(captured))

        out = await siem_hec_post(
            SiemHecPostInput(event={"sentient_verdict": "tp"})
        )
        assert isinstance(out, SiemHecPostOutput)
        assert out.success is True
        assert out.status_code == 200
        assert "/services/collector/event" in captured["url"]
        assert captured["url"].startswith("https://hec.local:8088")
        assert captured["headers"]["Authorization"] == "Splunk hec-token"
        assert captured["json"]["event"] == {"sentient_verdict": "tp"}
        assert captured["json"]["index"] == "triage_verdicts"
        # SPLUNK_VERIFY_TLS=false in env → verify pass-through must be False.
        assert captured["verify"] is False

    async def test_missing_hec_config_raises_internal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Bare-minimum env (SPLUNK_HOST + SPLUNK_TOKEN required by SplunkSettings).
        monkeypatch.setenv("SPLUNK_HOST", "splunk.local")
        monkeypatch.setenv("SPLUNK_TOKEN", "token")
        monkeypatch.setenv("SPLUNK_HEC_HOST", "")
        monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")
        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "internal"

    async def test_timeout_maps(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        class _BoomClient:
            def __init__(self, *_a: Any, **_kw: Any) -> None:
                pass

            async def __aenter__(self) -> _BoomClient:
                return self

            async def __aexit__(self, *_a: Any) -> None:
                return None

            async def post(self, *_a: Any, **_k: Any) -> Any:
                raise httpx.TimeoutException("slow")

        monkeypatch.setattr(mod.httpx, "AsyncClient", _BoomClient)
        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "search_timeout"

    async def test_401_maps_auth_failure(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        captured: dict[str, Any] = {"response": _Resp(401, "no")}
        monkeypatch.setattr(mod.httpx, "AsyncClient", _stub_client_factory(captured))

        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "auth_failure"

    async def test_4xx_maps_splunk_4xx(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        captured: dict[str, Any] = {"response": _Resp(400, "bad event")}
        monkeypatch.setattr(mod.httpx, "AsyncClient", _stub_client_factory(captured))
        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "splunk_4xx"

    async def test_5xx_maps_splunk_5xx(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        captured: dict[str, Any] = {"response": _Resp(503, "down")}
        monkeypatch.setattr(mod.httpx, "AsyncClient", _stub_client_factory(captured))
        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "splunk_5xx"

    async def test_transport_error_maps_internal(
        self, hec_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_hec_post as mod

        class _BoomClient:
            def __init__(self, *_a: Any, **_kw: Any) -> None:
                pass

            async def __aenter__(self) -> _BoomClient:
                return self

            async def __aexit__(self, *_a: Any) -> None:
                return None

            async def post(self, *_a: Any, **_k: Any) -> Any:
                raise httpx.ConnectError("can't reach hec")

        monkeypatch.setattr(mod.httpx, "AsyncClient", _BoomClient)
        with pytest.raises(SiemToolError) as exc:
            await siem_hec_post(SiemHecPostInput(event={"x": 1}))
        assert exc.value.kind == "internal"
