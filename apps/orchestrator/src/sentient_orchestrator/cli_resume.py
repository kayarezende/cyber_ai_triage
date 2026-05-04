"""Wk-8 CLI hack to resume an interrupted investigation.

Wk-9 web UI replaces the call site (POST `/api/approvals/{id}` enqueues a
`ResumeJob` on `QUEUE_RESUMES`; the worker drains it via the same
`resume_investigation()` function this CLI calls). Kept around for dev
debugging and the founder live-gate.

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
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import UTC, datetime
from uuid import UUID, uuid4

import psycopg

from sentient_common.jobs import ResumeJob
from sentient_common.logging import configure_logging, get_logger
from sentient_orchestrator.investigation.runner import (
    ResumeAlreadySubmitted,
    _strip_psycopg_dsn,
    claim_resume_intent,
    resume_investigation,
)

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


def _load_tenant_id(investigation_id: UUID) -> UUID:
    """Bootstrap tenant_id from investigation_id outside any tenant session.

    The CLI doesn't know the tenant ahead of time. The API path always does
    (the tenant is on `request.state.tenant_id` from middleware). This dev
    helper bypasses RLS via the postgres role; production wk-9 path uses
    `resume_investigation(job)` directly with `job.tenant_id` already set.
    """
    dsn = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    if not dsn:
        msg = "DATABASE_URL not set"
        raise RuntimeError(msg)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tenant_id FROM investigations WHERE id = %s",
            (str(investigation_id),),
        )
        row = cur.fetchone()
        if row is None:
            msg = f"investigation {investigation_id} not found"
            raise RuntimeError(msg)
        return UUID(str(row[0]))


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

    tenant_id = _load_tenant_id(investigation_id)
    trace_id = uuid4().hex

    # Cluster D HIGH-13: dedup + audit-row insert via the shared helper
    # the API path uses. Without this, the CLI could resume an
    # investigation a second analyst had already decided through the web
    # UI, and no `human_decision_submitted` audit row would record it.
    try:
        claim_resume_intent(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            approved=args.approve,
            analyst_id=args.analyst_id,
            notes=args.notes,
            actor="cli:resume",
            trace_id=trace_id,
        )
    except ResumeAlreadySubmitted:
        print(
            f"decision already submitted for {investigation_id}",
            file=sys.stderr,
        )
        return 3

    job = ResumeJob(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        approved=args.approve,
        analyst_id=args.analyst_id,
        notes=args.notes,
        enqueued_at=datetime.now(UTC),
        trace_id=trace_id,
    )
    return asyncio.run(resume_investigation(job))


if __name__ == "__main__":
    sys.exit(main())
