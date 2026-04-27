"""Wk-9 tests for the replay router."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def patch_replay_session(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"thread_id": "thread-test"}

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def execute(_stmt: Any, _params: dict[str, Any] | None = None) -> Any:
            return MagicMock(
                first=lambda: (state.get("thread_id"),)
                if state.get("thread_id") is not None
                else None
            )

        conn.execute.side_effect = execute
        yield conn

    monkeypatch.setattr(
        "sentient_api.routers.replay.tenant_session", fake_session
    )
    return state


def test_list_503_when_checkpointer_missing(
    wk9_client: TestClient, patch_replay_session: dict[str, Any]
) -> None:
    r = wk9_client.get(f"/api/replay/{uuid4()}/checkpoints")
    assert r.status_code == 503


def test_list_404_when_thread_missing(
    wk9_client: TestClient,
    patch_replay_session: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_replay_session["thread_id"] = None

    fake_saver = MagicMock()
    monkeypatch.setattr(
        "sentient_api.routers.replay.get_checkpointer", lambda _app: fake_saver
    )
    # The investigation row exists but has no thread_id → 404 thread_not_started
    @contextmanager
    def fake_session_no_thread(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")
        conn.execute.return_value = MagicMock(first=lambda: (None,))
        yield conn

    monkeypatch.setattr(
        "sentient_api.routers.replay.tenant_session", fake_session_no_thread
    )

    r = wk9_client.get(f"/api/replay/{uuid4()}/checkpoints")
    assert r.status_code == 404


def test_list_returns_checkpoint_summaries(
    wk9_client: TestClient,
    patch_replay_session: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_saver = MagicMock()

    async def alist(_config: Any, limit: int = 100) -> Any:
        for i in range(2):
            tup = MagicMock()
            tup.config = {"configurable": {"checkpoint_id": f"cp-{i}"}}
            tup.checkpoint = {
                "ts": f"2026-04-27T12:00:0{i}+00:00",
                "channel_values": {"messages": [], "tool_call_count": i},
            }
            tup.metadata = {"step": i, "writes": {"plan": {"v": i}}}
            tup.parent_config = (
                {"configurable": {"checkpoint_id": f"cp-{i-1}"}} if i else None
            )
            yield tup

    fake_saver.alist = alist
    monkeypatch.setattr(
        "sentient_api.routers.replay.get_checkpointer", lambda _app: fake_saver
    )

    r = wk9_client.get(f"/api/replay/{uuid4()}/checkpoints")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 2
    assert items[0]["checkpoint_id"] == "cp-0"
    assert items[1]["parent_checkpoint_id"] == "cp-0"
    assert items[1]["state_keys"] == ["messages", "tool_call_count"]
    assert items[0]["node_writes"] == ["plan"]


def test_get_checkpoint_404(
    wk9_client: TestClient,
    patch_replay_session: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_saver = MagicMock()

    async def aget_tuple(_config: Any) -> Any:
        return None

    fake_saver.aget_tuple = aget_tuple
    monkeypatch.setattr(
        "sentient_api.routers.replay.get_checkpointer", lambda _app: fake_saver
    )

    r = wk9_client.get(f"/api/replay/{uuid4()}/checkpoints/cp-99")
    assert r.status_code == 404


def test_get_checkpoint_returns_full_state(
    wk9_client: TestClient,
    patch_replay_session: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_saver = MagicMock()

    async def aget_tuple(_config: Any) -> Any:
        tup = MagicMock()
        tup.config = {"configurable": {"checkpoint_id": "cp-1"}}
        tup.checkpoint = {
            "ts": "2026-04-27T12:00:01+00:00",
            "channel_values": {"messages": [{"role": "user", "content": "hi"}]},
        }
        tup.metadata = {"step": 1, "writes": {"agent": {"x": 1}}}
        tup.parent_config = {"configurable": {"checkpoint_id": "cp-0"}}
        return tup

    fake_saver.aget_tuple = aget_tuple
    monkeypatch.setattr(
        "sentient_api.routers.replay.get_checkpointer", lambda _app: fake_saver
    )

    r = wk9_client.get(f"/api/replay/{uuid4()}/checkpoints/cp-1")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["checkpoint_id"] == "cp-1"
    assert body["parent_checkpoint_id"] == "cp-0"
    assert body["channel_values"]["messages"][0]["content"] == "hi"
