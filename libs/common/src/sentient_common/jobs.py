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
from pydantic import BaseModel, ConfigDict

QUEUE_INVESTIGATIONS = "sentient:jobs:investigations"


class IngestJob(BaseModel):
    """Investigation request enqueued by the ingest webhook."""

    incident_id: UUID
    tenant_id: UUID
    enqueued_at: datetime
    trace_id: str

    model_config = ConfigDict(extra="forbid")


def enqueue_investigation(client: redis.Redis, job: IngestJob) -> None:
    """LPUSH the job onto the investigations queue."""
    client.lpush(QUEUE_INVESTIGATIONS, job.model_dump_json())


__all__ = ["IngestJob", "QUEUE_INVESTIGATIONS", "enqueue_investigation"]
