"""CLI entrypoint: `python -m sentient_orchestrator.verify`.

Runs the wk-2 framework-stack verification once against live OpenRouter +
LangSmith + Postgres + the in-process echo MCP server. Prints a structured
log line + LangSmith URL on success.

Exit codes:
    0 — verify run completed AND structured_output_ok=True AND tool_call_count>=1.
    1 — verify run failed (graph raised, OpenRouter unreachable, etc.).
    2 — pre-flight failed (LangSmith not enabled, missing env, etc.).
"""

from __future__ import annotations

import asyncio
import os

from sentient_common.logging import configure_logging, get_logger
from sentient_orchestrator.tracing import init_tracing
from sentient_orchestrator.verify.runner import verify_run

configure_logging(service="orchestrator-verify")
log = get_logger(__name__)


def _langsmith_project_url(project: str) -> str:
    # LangSmith's per-project URL; the founder filters by metadata.thread_id
    # in the UI. We don't construct the filter param because LangSmith's TS-
    # DSL changes between UI versions and a wrong URL is worse than no URL.
    base = os.environ.get("LANGSMITH_HOST_URL", "https://smith.langchain.com")
    return f"{base}/o/-/projects/p/{project}"


async def _run() -> int:
    if not init_tracing():
        log.error(
            "verify aborted",
            reason=(
                "LANGSMITH_TRACING must be true with a real LANGSMITH_API_KEY "
                "(ls__/lsv2_ prefix or any non-CHANGEME value) for the verify gate"
            ),
        )
        return 2

    or_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not or_key or or_key.startswith("CHANGEME_"):
        log.error("verify aborted", reason="OPENROUTER_API_KEY missing or placeholder")
        return 2

    if "DATABASE_URL" not in os.environ:
        log.error("verify aborted", reason="DATABASE_URL missing")
        return 2

    summary = await verify_run()

    if not summary["completed"]:
        log.error("verify failed", **summary)
        return 1

    if not summary["structured_output_ok"] or summary["tool_call_count"] < 1:
        log.error("verify did not meet success criteria", **summary)
        return 1

    log.info(
        "verify ok",
        thread_id=summary["thread_id"],
        langsmith_project_url=_langsmith_project_url(summary["langsmith_project"]),
        langsmith_filter_hint=(
            f'open the project URL above and filter by metadata.thread_id == '
            f'{summary["thread_id"]!r}'
        ),
    )
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
