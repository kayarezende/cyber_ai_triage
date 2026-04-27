"""Wk-2 verify-harness smoke tests.

These run the full LangGraph + ChatOpenAI@OpenRouter + langchain-mcp-adapters +
PostgresSaver path with the in-process echo MCP server. They skip cleanly when
either Postgres or OpenRouter is unavailable (CI without keys) — founder runs
them locally with a real `.env` to gate Day 1 of wk 2.

Two tests:

1. `test_verify_smoke_completes` — happy path: structured-output + tool-call +
   checkpoint persistence + LangSmith-disabled summary.
2. `test_verify_smoke_resumes_after_inject_failure` — drives the
   `VERIFY_INJECT_FAILURE` env override so `call_echo_tool` raises on the
   first run; the second run uses `resume=True` (→ `ainvoke(None, config)`)
   to replay from the last checkpoint. **Asserts `extract_ip` runs exactly
   once total** — proves LangGraph's checkpointer reload semantics work end
   to end. This is the load-bearing wk-2 invariant for wk-6's production
   StateGraph: a container restart mid-investigation must not re-run an
   already-completed (and billed) LLM node.
"""

from __future__ import annotations

import os
import uuid

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from sentient_orchestrator.verify.graph import (
    EXPECTED_SRC_IP,
    node_call_counts,
    reset_node_call_counts,
)
from sentient_orchestrator.verify.runner import _strip_psycopg_dsn, verify_run

pytestmark = pytest.mark.asyncio


def _fresh_thread_id() -> str:
    return f"verify-test-{uuid.uuid4().hex[:8]}"


async def _wipe_thread(database_url: str, thread_id: str) -> None:
    dsn = _strip_psycopg_dsn(database_url)
    async with AsyncPostgresSaver.from_conn_string(dsn) as saver:
        await saver.adelete_thread(thread_id)


@pytest.fixture(autouse=True)
def _reset_node_counts() -> None:
    reset_node_call_counts()


async def test_verify_smoke_completes(
    require_database_url: str,
    require_openrouter_key: str,
) -> None:
    thread_id = _fresh_thread_id()
    try:
        summary = await verify_run(thread_id=thread_id)
    finally:
        await _wipe_thread(require_database_url, thread_id)

    assert summary["completed"] is True, summary
    assert summary["src_ip"] == EXPECTED_SRC_IP, summary
    assert summary["structured_output_ok"] is True, summary
    assert summary["tool_call_count"] >= 1, summary
    assert summary["echo_result"] is not None
    assert "echoed:" in summary["echo_result"]
    # 3 nodes + START → at least 3 checkpoint rows for this thread.
    assert summary["checkpoint_count"] >= 3, summary
    # Each node fired exactly once.
    assert node_call_counts["extract_ip"] == 1, dict(node_call_counts)
    assert node_call_counts["call_echo_tool"] == 1, dict(node_call_counts)
    assert node_call_counts["done"] == 1, dict(node_call_counts)


async def test_verify_smoke_resumes_after_inject_failure(
    require_database_url: str,
    require_openrouter_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    thread_id = _fresh_thread_id()
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    try:
        # Run 1 — fail at call_echo_tool. extract_ip succeeds + checkpoints;
        # call_echo_tool starts running then raises.
        monkeypatch.setenv("VERIFY_INJECT_FAILURE", "1")
        summary_fail = await verify_run(thread_id=thread_id)
        assert summary_fail["completed"] is False, summary_fail
        assert summary_fail["error"] is not None
        assert "VERIFY_INJECT_FAILURE" in (summary_fail["error"] or "")
        # extract_ip ran once successfully (state checkpointed); call_echo_tool
        # entered once and raised.
        assert node_call_counts["extract_ip"] == 1, dict(node_call_counts)
        assert node_call_counts["call_echo_tool"] == 1, dict(node_call_counts)
        assert node_call_counts["done"] == 0, dict(node_call_counts)

        # Verify state was actually checkpointed with src_ip populated.
        dsn = _strip_psycopg_dsn(require_database_url)
        async with AsyncPostgresSaver.from_conn_string(dsn) as saver:
            tup = await saver.aget_tuple(config)
            assert tup is not None
            assert tup.checkpoint["channel_values"].get("src_ip") == EXPECTED_SRC_IP

        # Run 2 — resume mode. LangGraph reads the post-extract_ip checkpoint
        # and re-enters at call_echo_tool, NOT at START. Asserting
        # `extract_ip` count stays at 1 is the load-bearing claim.
        monkeypatch.delenv("VERIFY_INJECT_FAILURE", raising=False)
        summary_ok = await verify_run(thread_id=thread_id, resume=True)

        assert summary_ok["completed"] is True, summary_ok
        assert summary_ok["src_ip"] == EXPECTED_SRC_IP, summary_ok
        assert summary_ok["echo_result"] is not None
        assert "echoed:" in summary_ok["echo_result"]
        assert summary_ok["checkpoint_count"] >= summary_fail["checkpoint_count"]

        # **The invariant**: extract_ip did NOT re-run.
        assert node_call_counts["extract_ip"] == 1, (
            f"extract_ip re-ran on resume; counts: {dict(node_call_counts)}"
        )
        assert node_call_counts["call_echo_tool"] == 2, dict(node_call_counts)
        assert node_call_counts["done"] == 1, dict(node_call_counts)
    finally:
        # Belt-and-braces — env var should already be gone via monkeypatch teardown.
        os.environ.pop("VERIFY_INJECT_FAILURE", None)
        await _wipe_thread(require_database_url, thread_id)
