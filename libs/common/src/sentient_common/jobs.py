"""Redis queue payload schemas + helpers.

Lives in `libs/common` so producers (api) and consumers (worker) share the
contract without dragging each other's heavy deps (worker pulls in the
LangGraph + LangChain stack via `sentient-orchestrator`; api should not).

Wire-format is Pydantic's `model_dump_json()` — UUID + datetime serialise
to strings.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import redis
from pydantic import BaseModel, ConfigDict, Field

QUEUE_INVESTIGATIONS = "sentient:jobs:investigations"
QUEUE_RESUMES = "sentient:jobs:investigation_resumes"


class IngestJob(BaseModel):
    """Investigation request enqueued by the ingest webhook."""

    incident_id: UUID
    tenant_id: UUID
    enqueued_at: datetime
    trace_id: str

    model_config = ConfigDict(extra="forbid")


class ResumeJob(BaseModel):
    """Resume request enqueued by the wk-9 approvals API.

    Travels on `QUEUE_RESUMES`. The worker rebuilds the LangGraph thread
    via `AsyncPostgresSaver` + MCP tools and calls
    `Command(resume={"approved": ..., "analyst_id": ..., "notes": ...})`
    against the paused graph. `notes` is sanitized + capped server-side
    before reaching `await_approval_node` (defence in depth — `nodes.py`
    also caps at 1024).
    """

    investigation_id: UUID
    tenant_id: UUID
    approved: bool
    analyst_id: str | None = None
    notes: str = Field(default="", max_length=1024)
    enqueued_at: datetime
    trace_id: str

    model_config = ConfigDict(extra="forbid")


def enqueue_investigation(client: redis.Redis, job: IngestJob) -> None:
    """LPUSH the job onto the investigations queue."""
    client.lpush(QUEUE_INVESTIGATIONS, job.model_dump_json())


def enqueue_resume(client: redis.Redis, job: ResumeJob) -> None:
    """LPUSH the resume job onto the resumes queue."""
    client.lpush(QUEUE_RESUMES, job.model_dump_json())


__all__ = [
    "QUEUE_INVESTIGATIONS",
    "QUEUE_RESUMES",
    "IngestJob",
    "ResumeJob",
    "enqueue_investigation",
    "enqueue_resume",
]
