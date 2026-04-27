"""Wk-8 unit tests for `siem_notable_update`."""

from __future__ import annotations

import io
from typing import Any

import pytest
from pydantic import ValidationError

from sentient_mcp_splunk.errors import SiemToolError
from sentient_mcp_splunk.schemas.siem_notable_update import (
    SiemNotableUpdateInput,
    SiemNotableUpdateOutput,
)
from sentient_mcp_splunk.tools.siem_notable_update import siem_notable_update


@pytest.fixture(autouse=True)
def _reset_notable_cache() -> None:
    from sentient_mcp_splunk.tools.siem_get_notable import _reset_notable_index_cache

    _reset_notable_index_cache()


class TestSiemNotableUpdateInput:
    @pytest.mark.parametrize(
        ("notable_id", "comment", "status", "urgency"),
        [
            ("notable-1", "verdict: tp", None, None),
            ("evt:001", "x" * 4096, "in_progress", "high"),
            ("a.b@c", "ok", "resolved", None),
            ("hostname-01", "ok", None, "informational"),
        ],
    )
    def test_valid(
        self,
        notable_id: str,
        comment: str,
        status: str | None,
        urgency: str | None,
    ) -> None:
        m = SiemNotableUpdateInput(
            notable_id=notable_id,
            comment=comment,
            status=status,  # type: ignore[arg-type]
            urgency=urgency,  # type: ignore[arg-type]
        )
        assert m.notable_id == notable_id
        assert m.comment == comment

    @pytest.mark.parametrize(
        ("notable_id", "comment", "status", "urgency"),
        [
            ("", "ok", None, None),  # empty id
            ('id" OR 1=1', "ok", None, None),  # SPL injection shape
            ("id with space", "ok", None, None),
            ("good-id", "", None, None),  # empty comment
            ("good-id", "x" * 4097, None, None),  # comment too long
            ("good-id", "ok", "totally-bogus", None),  # bad status enum
            ("good-id", "ok", None, "EXTREMELY_HIGH"),  # bad urgency enum
        ],
    )
    def test_rejected(
        self,
        notable_id: str,
        comment: str,
        status: str | None,
        urgency: str | None,
    ) -> None:
        with pytest.raises(ValidationError):
            SiemNotableUpdateInput(
                notable_id=notable_id,
                comment=comment,
                status=status,  # type: ignore[arg-type]
                urgency=urgency,  # type: ignore[arg-type]
            )


@pytest.mark.asyncio
class TestSiemNotableUpdateHandler:
    async def test_degraded_when_no_notable_index(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_notable_update as mod
        from sentient_mcp_splunk.tools.siem_get_notable import (
            _NotableIndexAbsentError,
        )

        def boom(*_a: Any, **_k: Any) -> object:
            raise _NotableIndexAbsentError

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        out = await siem_notable_update(
            SiemNotableUpdateInput(notable_id="n-1", comment="c")
        )
        assert isinstance(out, SiemNotableUpdateOutput)
        assert out.degraded is True
        assert out.success is False
        assert out.notes is not None
        assert "siem_hec_post" in out.notes

    async def test_happy_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sentient_mcp_splunk.tools import siem_notable_update as mod

        captured: dict[str, Any] = {}

        def fake_run(
            notable_id: str,
            comment: str,
            status: str | None,
            urgency: str | None,
        ) -> dict[str, Any]:
            captured["args"] = (notable_id, comment, status, urgency)
            return {"status": 200, "body": '{"ok":true}'}

        monkeypatch.setattr(mod, "_run_update_sync", fake_run)
        out = await siem_notable_update(
            SiemNotableUpdateInput(
                notable_id="n-1",
                comment="verdict: tp",
                status="in_progress",
                urgency="high",
            )
        )
        assert out.success is True
        assert out.degraded is False
        assert out.splunk_response is not None
        assert out.splunk_response["status"] == 200
        assert captured["args"] == ("n-1", "verdict: tp", "in_progress", "high")

    async def test_non_2xx_marks_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_notable_update as mod

        def fake_run(*_a: Any, **_k: Any) -> dict[str, Any]:
            return {"status": 500, "body": "boom"}

        monkeypatch.setattr(mod, "_run_update_sync", fake_run)
        out = await siem_notable_update(
            SiemNotableUpdateInput(notable_id="n-1", comment="c")
        )
        assert out.success is False
        assert out.degraded is False
        assert out.notes is not None
        assert "500" in out.notes

    async def test_auth_failure_maps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from splunklib.binding import AuthenticationError, HTTPError

        from sentient_mcp_splunk.tools import siem_notable_update as mod

        class _R:
            def __init__(self, status: int) -> None:
                self.status = status
                self.reason = "x"
                self.headers: list[tuple[str, str]] = []
                self.body = io.BytesIO(b"x")

        cause = HTTPError(_R(401), "401")

        def boom(*_a: Any, **_k: Any) -> object:
            raise AuthenticationError("bad token", cause)

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_notable_update(
                SiemNotableUpdateInput(notable_id="n-1", comment="c")
            )
        assert exc.value.kind == "auth_failure"

    async def test_timeout_maps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sentient_mcp_splunk.tools import siem_notable_update as mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise TimeoutError("slow")

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_notable_update(
                SiemNotableUpdateInput(notable_id="n-1", comment="c")
            )
        assert exc.value.kind == "search_timeout"

    async def test_http_4xx_maps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from splunklib.binding import HTTPError

        from sentient_mcp_splunk.tools import siem_notable_update as mod

        class _R:
            def __init__(self, status: int) -> None:
                self.status = status
                self.reason = "bad"
                self.headers: list[tuple[str, str]] = []
                self.body = io.BytesIO(b"bad")

        def boom(*_a: Any, **_k: Any) -> object:
            raise HTTPError(_R(404), "not found")

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_notable_update(
                SiemNotableUpdateInput(notable_id="n-1", comment="c")
            )
        assert exc.value.kind == "splunk_4xx"

    async def test_internal_maps_unexpected_exceptions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.tools import siem_notable_update as mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise RuntimeError("surprise")

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_notable_update(
                SiemNotableUpdateInput(notable_id="n-1", comment="c")
            )
        assert exc.value.kind == "internal"

    async def test_already_typed_error_not_re_wrapped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentient_mcp_splunk.errors import auth_failure
        from sentient_mcp_splunk.tools import siem_notable_update as mod

        def boom(*_a: Any, **_k: Any) -> object:
            raise auth_failure("rotated")

        monkeypatch.setattr(mod, "_run_update_sync", boom)
        with pytest.raises(SiemToolError) as exc:
            await siem_notable_update(
                SiemNotableUpdateInput(notable_id="n-1", comment="c")
            )
        # If `except Exception` ran first this would have been re-classified.
        assert exc.value.kind == "auth_failure"
