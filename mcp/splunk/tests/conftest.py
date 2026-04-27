"""Shared fixtures for mcp/splunk tests.

`integration` marker is registered at the root pyproject; founder runs
`uv run pytest -m integration mcp/splunk/tests/integration` against live
Splunk. Default `pytest` invocations skip integration via root `addopts`.
"""

from __future__ import annotations

import os
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _splunk_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Always set required Splunk env so `SplunkSettings()` constructs.

    Unit tests mock the Splunk SDK before any real network call; the env
    just has to satisfy `pydantic-settings` validation.
    """
    monkeypatch.setenv("SPLUNK_HOST", "localhost")
    monkeypatch.setenv("SPLUNK_PORT", "8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "test-token")
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", "false")
    monkeypatch.setenv("SPLUNK_HEC_HOST", "localhost")
    monkeypatch.setenv("SPLUNK_HEC_PORT", "8088")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "test-hec-token")


@pytest.fixture
def fake_oneshot(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace `tools.siem_query._run_oneshot_sync` with a canned generator.

    Returns a setter the test calls with the rows it wants the next
    `siem_query` invocation to see. The fixture also stubs
    `splunklib.results.JSONResultsReader` so iterating the response yields
    those rows directly.
    """
    state: dict[str, Any] = {"rows": []}

    def fake_run(*_args: Any, **_kwargs: Any) -> object:
        return state["rows"]  # the "response" we return is just the rows.

    def fake_reader(rows: object) -> object:
        # rows is whatever fake_run returned — an iterable of dicts.
        return iter(rows)  # type: ignore[arg-type]

    from sentient_mcp_splunk.tools import siem_query as siem_query_mod

    monkeypatch.setattr(siem_query_mod, "_run_oneshot_sync", fake_run)
    monkeypatch.setattr(
        siem_query_mod.splunk_results, "JSONResultsReader", fake_reader
    )

    def set_rows(rows: list[dict[str, Any]]) -> None:
        state["rows"] = rows

    return set_rows


@pytest.fixture
def integration_marker_skip() -> None:
    """Skip when SPLUNK_HOST is unreachable — for tests run without the
    `-m integration` filter that still get collected."""
    if not os.environ.get("SPLUNK_HOST"):
        pytest.skip("SPLUNK_HOST not set — integration test skipped")
