"""Wk-8 CLI hack to resume an interrupted investigation.

Wk-9 web UI replaces this. For wk-8 the CLI is the only way to deliver an
analyst decision into a paused LangGraph thread.

Usage:
    uv run python -m sentient_orchestrator.cli_resume \
        --investigation-id <uuid> \
        --approve \
        --analyst-id <uuid> \
        --notes "looks good"

    uv run python -m sentient_orchestrator.cli_resume \
        --investigation-id <uuid> \
        --reject \
        --analyst-id <uuid> \
        --notes "false positive"

The script reads the LangGraph thread id off `investigations.langgraph_thread_id`,
re-attaches via `AsyncPostgresSaver`, re-builds the same MCP tool set the
runner uses, then `Command(resume=...)`s the graph. After the graph finishes,
calls `_finalize_after_graph` so the verdict / writeback / approval surface
lands on the investigations row.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any, cast
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.types import Command
from sqlalchemy import text

from sentient_common.db import tenant_session
from sentient_common.logging import configure_logging, get_logger
from sentient_ocsf.detection_finding import validate_detection_finding
from sentient_orchestrator.investigation.graph import build_investigation_graph
from sentient_orchestrator.investigation.mcp_client import build_mcp_client
from sentient_orchestrator.investigation.runner import (
    _finalize_after_graph,
    _is_interrupted,
    _strip_psycopg_dsn,
)
from sentient_orchestrator.investigation.state import InvestigationState
from sentient_orchestrator.mitre_lookup import fetch_technique_descriptions

log = get_logger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentient_orchestrator.cli_resume",
        description=(
            "Resume an interrupted investigation by feeding the analyst "
            "decision into the LangGraph thread. Wk-8 dev-only hack; wk-9 "
            "replaces with a web UI."
        ),
    )
    parser.add_argument(
        "--investigation-id",
        required=True,
        help="UUID of the investigation row to resume.",
    )
    decision = parser.add_mutually_exclusive_group(required=True)
    decision.add_argument(
        "--approve",
        action="store_true",
        help="Approve the verdict; writeback proceeds.",
    )
    decision.add_argument(
        "--reject",
        action="store_true",
        help="Reject the verdict; writeback is skipped.",
    )
    parser.add_argument(
        "--analyst-id",
        default=None,
        help="UUID of the approving / rejecting analyst. Optional but recommended.",
    )
    parser.add_argument(
        "--notes",
        default="",
        help="Free-text notes from the analyst (sanitized + capped to 1024 chars).",
    )
    return parser.parse_args(argv)


def _load_investigation_context(investigation_id: UUID) -> tuple[UUID, UUID, str, Any]:
    """Pull tenant_id, incident_id, thread_id, and OCSF finding off the DB."""
    # Note: we don't yet know the tenant_id, so this query bypasses RLS by
    # using the postgres role's session var fallback. The investigation row
    # itself carries tenant_id. This script is dev-only — production wk-9
    # API authenticates the analyst before resuming.
    import psycopg

    dsn = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    if not dsn:
        msg = "DATABASE_URL not set"
        raise RuntimeError(msg)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tenant_id, incident_id, langgraph_thread_id "
            "  FROM investigations WHERE id = %s",
            (str(investigation_id),),
        )
        row = cur.fetchone()
        if row is None:
            msg = f"investigation {investigation_id} not found"
            raise RuntimeError(msg)
        tenant_id = UUID(str(row[0]))
        incident_id = UUID(str(row[1]))
        thread_id = str(row[2]) if row[2] else ""
        if not thread_id:
            msg = (
                f"investigation {investigation_id} has no langgraph_thread_id; "
                "not interruptable"
            )
            raise RuntimeError(msg)
        cur.execute(
            "SELECT ocsf_normalized FROM incidents WHERE id = %s",
            (str(incident_id),),
        )
        ocsf_row = cur.fetchone()
        if ocsf_row is None or not ocsf_row[0]:
            msg = f"incident {incident_id} missing ocsf_normalized"
            raise RuntimeError(msg)
    finding = validate_detection_finding(ocsf_row[0])
    return tenant_id, incident_id, thread_id, finding


async def _run_resume(
    investigation_id: UUID, *, approved: bool, analyst_id: str | None, notes: str
) -> int:
    tenant_id, incident_id, thread_id, finding = _load_investigation_context(
        investigation_id
    )

    # Mirror the runner's MITRE descs hydration for the resumed config.
    with tenant_session(tenant_id) as conn:
        triage_row = conn.execute(
            text(
                "SELECT mitre_techniques FROM investigations WHERE id = :id"
            ),
            {"id": str(investigation_id)},
        ).first()
        triage_techniques = list(triage_row[0] or []) if triage_row else []
        mitre_descs = (
            fetch_technique_descriptions(conn, triage_techniques)
            if triage_techniques
            else {}
        )

    mcp_client = build_mcp_client()
    tools = await mcp_client.get_tools()

    db_url = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    async with AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
        graph = build_investigation_graph().compile(checkpointer=checkpointer)
        config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "tenant_id": str(tenant_id),
                "investigation_id": str(investigation_id),
                "finding": finding,
                "tools": tools,
                "mitre_descs": mitre_descs,
            }
        }
        resume_payload: dict[str, Any] = {
            "approved": approved,
            "analyst_id": analyst_id,
            "notes": notes,
        }
        log.info(
            "resuming investigation",
            investigation_id=str(investigation_id),
            thread_id=thread_id,
            approved=approved,
        )
        final_state = await graph.ainvoke(Command(resume=resume_payload), config=config)

    if _is_interrupted(final_state):
        log.warning(
            "graph re-entered interrupted state after resume",
            investigation_id=str(investigation_id),
        )
        return 2

    await _finalize_after_graph(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        finding=finding,
        final_state=cast(InvestigationState, final_state),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    configure_logging("orchestrator-cli-resume")
    args = _parse_args(argv)
    try:
        investigation_id = UUID(args.investigation_id)
    except ValueError:
        print("--investigation-id must be a UUID", file=sys.stderr)
        return 2
    if args.analyst_id:
        try:
            UUID(args.analyst_id)
        except ValueError:
            print("--analyst-id must be a UUID", file=sys.stderr)
            return 2
    return asyncio.run(
        _run_resume(
            investigation_id,
            approved=args.approve,
            analyst_id=args.analyst_id,
            notes=args.notes,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
