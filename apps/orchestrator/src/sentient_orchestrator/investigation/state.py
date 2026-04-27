"""Tier-2 investigation graph state + output schema.

`InvestigationState` is a TypedDict so PostgresSaver can serialize it without
custom encoders. `messages` carries the chat history in OpenAI wire format
(plain dicts) — matches what `LLMRouter.call` accepts and avoids LangChain
`BaseMessage` ↔ dict coercion overhead.

`InvestigationOutput` is the Pydantic contract emitted by the
`draft_verdict_node` LLM call (validated via `LLMRouter` schema-retry path).

The Pydantic schemas (`InvestigationOutput`, `ReviewOutput`, `Verdict`,
`ReviewStatus`, `HallucinationRisk`, `ConfidenceAssessment`) live in
`sentient_common.schemas.investigation` so the API can import them without
pulling LangGraph into the API container. Re-exported here so existing
call sites under `sentient_orchestrator.investigation.state` keep working.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from sentient_common.schemas.investigation import (
    ConfidenceAssessment,
    HallucinationRisk,
    InvestigationOutput,
    ReviewOutput,
    ReviewStatus,
    Severity,
    Verdict,
)

#: Hard cap on total tool calls per investigation. Prevents runaway loops
#: while still allowing genuine multi-step investigations. Skeleton value;
#: revisit alongside per-investigation token caps in wk-7.
MAX_TOOL_CALLS = 10


class InvestigationState(TypedDict, total=False):
    """LangGraph StateGraph state for Tier-2 investigations.

    `messages` uses ``Annotated[..., operator.add]`` so each node returning
    `{"messages": [...]}` appends to the existing list rather than overwriting
    — standard LangGraph reducer pattern for chat history.
    """

    # Chat history. OpenAI wire format dicts so LLMRouter can pass straight
    # through. Includes assistant messages with `tool_calls` and tool-role
    # messages with `tool_call_id` + `content`.
    messages: Annotated[list[dict[str, Any]], operator.add]

    # Identifiers (UUID hex strings — TypedDict + JSON serialization friendly).
    investigation_id: str
    tenant_id: str
    incident_id: str

    # Tier-1 triage context — frozen across the run.
    triage_severity: Severity
    triage_confidence: int
    triage_mitre_guesses: list[str]
    triage_entities: list[str]
    triage_reasoning: str

    # Sanitized OCSF Detection Finding payload (dict — serialized form).
    incident_ocsf: dict[str, Any]

    # Cap counter — every tool call increments. Routes graph to correlate
    # node when reaching MAX_TOOL_CALLS.
    tool_call_count: int

    # Final verdict surface populated by `draft_verdict_node`.
    draft_verdict: dict[str, Any] | None

    # Wk-7. Review-role output populated by `review_node` (or skipped form
    # when the review LLM call fails — review is best-effort, never blocks
    # the verdict). Round-tripped through the LangGraph checkpointer.
    review_output: dict[str, Any] | None

    # Wk-8. Detection-rule matches populated by `apply_detection_rules_node`
    # (sits after `review`). Each entry: {rule_id, rule_name, matched_required,
    # matched_any, severity_override}.
    detection_rule_matches: list[dict[str, Any]]

    # Wk-8. HITL approval surface populated by `await_approval_node`.
    # `pending` is set inline before the LangGraph `interrupt()` fires;
    # `approved` / `rejected` arrive via the `Command(resume=...)` payload.
    # `auto` indicates the active HITL policy returned False (no human gate).
    approval_status: Literal["pending", "approved", "rejected", "auto"]
    approver_id: str | None
    approval_notes: str | None

    # Wk-8. Dual writeback surface populated by `writeback_node`. `attempts`
    # captures one entry per HEC / notable_update call: {tool, ok, detail}.
    writeback_status: Literal["pending", "succeeded", "failed", "skipped"]
    writeback_attempts: list[dict[str, Any]]


__all__ = [
    "MAX_TOOL_CALLS",
    "ConfidenceAssessment",
    "HallucinationRisk",
    "InvestigationOutput",
    "InvestigationState",
    "ReviewOutput",
    "ReviewStatus",
    "Severity",
    "Verdict",
]
