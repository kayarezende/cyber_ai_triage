"""mitre_lookup unit tests using a fake SQLAlchemy connection."""

from __future__ import annotations

from typing import Any

from sentient_orchestrator.mitre_lookup import (
    _truncate,
    fetch_technique_descriptions,
)


class _FakeResult:
    def __init__(self, rows: list[tuple[str, str | None, str | None]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str, str | None, str | None]]:
        return self._rows


class _FakeConn:
    def __init__(self, rows: list[tuple[str, str | None, str | None]]) -> None:
        self._rows = rows
        self.last_params: dict[str, Any] | None = None

    def execute(self, _stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.last_params = params
        return _FakeResult(self._rows)


def test_returns_name_and_description_joined() -> None:
    conn = _FakeConn(
        [
            ("T1059.001", "PowerShell", "Adversary uses PowerShell to execute code."),
            ("T1071", "Application Layer Protocol", "C2 over HTTP/DNS."),
        ]
    )
    out = fetch_technique_descriptions(conn, ["T1059.001", "T1071"])
    assert out["T1059.001"].startswith("PowerShell — ")
    assert "Adversary uses PowerShell" in out["T1059.001"]
    assert out["T1071"].startswith("Application Layer Protocol")


def test_returns_just_name_when_description_missing() -> None:
    conn = _FakeConn([("T1110", "Brute Force", None)])
    out = fetch_technique_descriptions(conn, ["T1110"])
    assert out["T1110"] == "Brute Force"


def test_drops_rows_with_no_name() -> None:
    conn = _FakeConn([("T1110", None, "desc only")])
    out = fetch_technique_descriptions(conn, ["T1110"])
    assert out == {}


def test_empty_input_short_circuits() -> None:
    conn = _FakeConn([])
    assert fetch_technique_descriptions(conn, []) == {}
    # No SELECT executed for empty input.
    assert conn.last_params is None


def test_passes_ids_as_list_param() -> None:
    conn = _FakeConn([])
    fetch_technique_descriptions(conn, ["T1059", "T1071"])
    assert conn.last_params == {"ids": ["T1059", "T1071"]}


def test_truncate_collapses_whitespace() -> None:
    assert _truncate("hello\n\n  world", 100) == "hello world"


def test_truncate_caps_at_limit() -> None:
    long = "x" * 500
    out = _truncate(long, 50)
    assert len(out) == 50
    assert out.endswith("…")
