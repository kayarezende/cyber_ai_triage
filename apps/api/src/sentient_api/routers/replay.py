"""Wk-9 LangGraph time-travel replay endpoints.

GET `/api/replay/{investigation_id}/checkpoints`              list summaries
GET `/api/replay/{investigation_id}/checkpoints/{checkpoint_id}` full snapshot

Reads through the lifespan-cached `AsyncPostgresSaver` (see
`apps/api/src/sentient_api/clients/checkpointer.py`). The thread_id comes
off `investigations.langgraph_thread_id` (set by `_claim_investigation`).
"""

from __future__ import annotations

from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text

from sentient_api.clients.checkpointer import get_checkpointer
from sentient_api.deps import TenantId
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger

router = APIRouter(tags=["replay"])
log = get_logger(__name__)


class CheckpointSummary(BaseModel):
    checkpoint_id: str
    parent_checkpoint_id: str | None
    step: int | None
    ts: str | None
    node_writes: list[str]
    state_keys: list[str]
    has_interrupt: bool

    model_config = ConfigDict(extra="forbid")


class CheckpointList(BaseModel):
    items: list[CheckpointSummary]


class CheckpointDetail(BaseModel):
    checkpoint_id: str
    parent_checkpoint_id: str | None
    step: int | None
    ts: str | None
    metadata: dict[str, Any]
    channel_values: dict[str, Any]


def _resolve_thread_id(tenant_id: UUID, investigation_id: UUID) -> str:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                SELECT langgraph_thread_id FROM investigations
                 WHERE id = :id
                """
            ),
            {"id": str(investigation_id)},
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    if not row[0]:
        raise HTTPException(
            status_code=404, detail="thread_not_started"
        )
    return str(row[0])


def _summarize_writes(writes: Any) -> list[str]:
    """LangGraph metadata.writes is a dict of channel_name -> value or list."""
    if not isinstance(writes, dict):
        return []
    return sorted({k for k, v in writes.items() if v is not None})


def _channel_keys(values: Any) -> list[str]:
    if not isinstance(values, dict):
        return []
    return sorted(values.keys())


@router.get(
    "/api/replay/{investigation_id}/checkpoints", response_model=CheckpointList
)
async def list_checkpoints(
    investigation_id: UUID,
    tenant_id: TenantId,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> CheckpointList:
    saver = get_checkpointer(request.app)
    if saver is None:
        raise HTTPException(
            status_code=503, detail="checkpointer_unavailable"
        )
    thread_id = _resolve_thread_id(tenant_id, investigation_id)
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    items: list[CheckpointSummary] = []
    async for tup in saver.alist(config, limit=limit):
        cp = tup.checkpoint
        meta = tup.metadata or {}
        parent_cfg = tup.parent_config
        parent_id = (
            parent_cfg["configurable"].get("checkpoint_id")
            if parent_cfg and "configurable" in parent_cfg
            else None
        )
        channel_values = cp.get("channel_values") if isinstance(cp, dict) else {}
        items.append(
            CheckpointSummary(
                checkpoint_id=str(tup.config["configurable"]["checkpoint_id"]),
                parent_checkpoint_id=str(parent_id) if parent_id else None,
                step=meta.get("step") if isinstance(meta, dict) else None,
                ts=cp.get("ts") if isinstance(cp, dict) else None,
                node_writes=_summarize_writes(
                    meta.get("writes") if isinstance(meta, dict) else None
                ),
                state_keys=_channel_keys(channel_values),
                has_interrupt=bool(
                    isinstance(channel_values, dict)
                    and "__interrupt__" in channel_values
                ),
            )
        )
    return CheckpointList(items=items)


@router.get(
    "/api/replay/{investigation_id}/checkpoints/{checkpoint_id}",
    response_model=CheckpointDetail,
)
async def get_checkpoint(
    investigation_id: UUID,
    checkpoint_id: str,
    tenant_id: TenantId,
    request: Request,
) -> CheckpointDetail:
    saver = get_checkpointer(request.app)
    if saver is None:
        raise HTTPException(
            status_code=503, detail="checkpointer_unavailable"
        )
    thread_id = _resolve_thread_id(tenant_id, investigation_id)
    config: RunnableConfig = {
        "configurable": {
            "thread_id": thread_id,
            "checkpoint_id": checkpoint_id,
        }
    }
    tup = await saver.aget_tuple(config)
    if tup is None:
        raise HTTPException(status_code=404, detail="checkpoint_not_found")
    cp = tup.checkpoint or {}
    meta = tup.metadata or {}
    parent_cfg = tup.parent_config
    parent_id = (
        parent_cfg["configurable"].get("checkpoint_id")
        if parent_cfg and "configurable" in parent_cfg
        else None
    )
    return CheckpointDetail(
        checkpoint_id=checkpoint_id,
        parent_checkpoint_id=str(parent_id) if parent_id else None,
        step=meta.get("step") if isinstance(meta, dict) else None,
        ts=cp.get("ts") if isinstance(cp, dict) else None,
        metadata=cast("dict[str, Any]", dict(meta)) if meta else {},
        channel_values=cp.get("channel_values") if isinstance(cp, dict) else {},
    )


__all__ = ["router"]
