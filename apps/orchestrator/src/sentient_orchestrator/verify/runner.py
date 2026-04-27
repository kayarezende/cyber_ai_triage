"""Async runner for the wk-2 verify harness — shared by CLI + pytest."""

from __future__ import annotations

import os
import sys
import uuid
from typing import Any

from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StdioConnection
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from sentient_common.logging import get_logger
from sentient_orchestrator.verify.graph import EXPECTED_SRC_IP, build_verify_graph
from sentient_orchestrator.verify.llm import build_chat_openrouter

log = get_logger(__name__)


def _strip_psycopg_dsn(database_url: str) -> str:
    """Match the pattern used in db/seeds/setup_checkpointer.py.

    SQLAlchemy form `postgresql+psycopg://...` is what Alembic + the apps use.
    Native psycopg (which langgraph-checkpoint-postgres uses) wants the bare
    `postgresql://` form.
    """
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _make_thread_id() -> str:
    return f"verify-{uuid.uuid4().hex[:8]}"


def _echo_connection() -> StdioConnection:
    return StdioConnection(
        transport="stdio",
        command=sys.executable,
        args=["-m", "sentient_orchestrator.verify.echo_mcp_server"],
    )


async def verify_run(
    *,
    thread_id: str | None = None,
    model: str | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    """Run the 3-node verify graph end-to-end against live OpenRouter.

    Args:
        thread_id: LangGraph thread; auto-generated when None.
        model: OpenRouter model override; default is the wk-2 dev model.
        resume: when True, pass `None` to `graph.ainvoke()` so LangGraph
            resumes from the last checkpoint for `thread_id` rather than
            starting from a fresh input. Use after a previous run on the
            same `thread_id` raised mid-flight (e.g.
            `VERIFY_INJECT_FAILURE=1`).

    Returns a structured summary dict suitable for logging + assertions.
    Caller is responsible for `init_tracing()` if LangSmith trace is desired.
    """
    tid = thread_id or _make_thread_id()
    db_url = _strip_psycopg_dsn(os.environ["DATABASE_URL"])
    # Mirror `tracing.init_tracing()`'s gating exactly — both reads must agree
    # or the summary line will lie about whether traces shipped.
    langsmith_key = os.environ.get("LANGSMITH_API_KEY", "")
    langsmith_enabled = (
        os.environ.get("LANGSMITH_TRACING", "").lower() in {"1", "true", "yes", "on"}
        and bool(langsmith_key)
        and not langsmith_key.startswith("CHANGEME_")
    )
    langsmith_project = os.environ.get("LANGSMITH_PROJECT", "default")

    llm_kwargs: dict[str, Any] = {}
    if model:
        llm_kwargs["model"] = model
    llm = build_chat_openrouter(**llm_kwargs)

    mcp_client = MultiServerMCPClient({"echo": _echo_connection()})
    tools = await mcp_client.get_tools()
    log.info("verify mcp tools loaded", count=len(tools), names=[t.name for t in tools])

    summary: dict[str, Any] = {
        "thread_id": tid,
        "structured_output_ok": False,
        "tool_call_count": 0,
        "checkpoint_count": 0,
        "src_ip": None,
        "echo_result": None,
        "langsmith_enabled": langsmith_enabled,
        "langsmith_project": langsmith_project,
        "completed": False,
        "error": None,
    }

    builder = build_verify_graph(llm, tools)

    async with AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
        graph = builder.compile(checkpointer=checkpointer)
        config: RunnableConfig = {"configurable": {"thread_id": tid}}

        # Resume → ainvoke(None, config) replays from the last checkpoint.
        # Fresh run → ainvoke({"messages": []}, config) starts from START.
        graph_input: Any = None if resume else {"messages": []}
        try:
            final_state = await graph.ainvoke(graph_input, config=config)
        except Exception as exc:
            summary["error"] = f"{type(exc).__name__}: {exc}"
            log.warning("verify graph raised", thread_id=tid, error=summary["error"])
        else:
            summary["completed"] = True
            summary["src_ip"] = final_state.get("src_ip")
            summary["echo_result"] = final_state.get("echo_result")
            summary["structured_output_ok"] = (
                summary["src_ip"] == EXPECTED_SRC_IP
            )
            summary["tool_call_count"] = sum(
                1 for m in final_state.get("messages", [])
                if isinstance(m, ToolMessage)
            )

        # Count checkpoints persisted for this thread_id. `alist` is bounded
        # by the thread's history so this is cheap even on long runs; wrap
        # in try/except so a transient DB blip doesn't poison `summary`.
        checkpoint_count = 0
        try:
            async for _ in checkpointer.alist(config):
                checkpoint_count += 1
        except Exception as exc:
            log.warning("checkpoint alist failed", thread_id=tid, error=str(exc))
            checkpoint_count = -1
        summary["checkpoint_count"] = checkpoint_count

    log.info(
        "verify_run_complete",
        **{k: v for k, v in summary.items() if k != "error" or v is not None},
    )
    return summary
