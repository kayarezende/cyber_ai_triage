"""Tier-2 investigation graph state + output schema.

`InvestigationState` is a TypedDict so PostgresSaver can serialize it without
custom encoders. `messages` carries the chat history in OpenAI wire format
(plain dicts) — matches what `LLMRouter.call` accepts and avoids LangChain
`BaseMessage` ↔ dict coercion overhead.

`InvestigationOutput` is the Pydantic contract emitted by the
`draft_verdict_node` LLM call (validated via `LLMRouter` schema-retry path).
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from sentient_orchestrator.triage.schemas import Severity

#: Hard cap on total tool calls per investigation. Prevents runaway loops
#: while still allowing genuine multi-step investigations. Skeleton value;
#: revisit alongside per-investigation token caps in wk-7.
MAX_TOOL_CALLS = 10


Verdict = Literal["true_positive", "false_positive", "benign", "inconclusive"]


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


class InvestigationOutput(BaseModel):
    """Tier-2 verdict surface emitted by the draft_verdict node."""

    verdict: Verdict = Field(
        ...,
        description=(
            "Final verdict. `true_positive` = confirmed malicious activity. "
            "`false_positive` = SIEM detection misfired. `benign` = legitimate "
            "activity that triggered the rule. `inconclusive` = evidence "
            "insufficient for a confident call."
        ),
    )
    confidence: Annotated[int, Field(ge=0, le=100)] = Field(
        ..., description="0-100. >=80 strong, 50-79 plausible, <50 weak."
    )
    severity: Severity = Field(
        ...,
        description=(
            "Refined severity. May differ from the Tier-1 triage severity "
            "after deeper investigation."
        ),
    )
    mitre_techniques: list[Annotated[str, Field(pattern=r"^T\d+(\.\d+)?$")]] = Field(
        default_factory=list,
        description=(
            "Refined MITRE technique list. Removes Tier-1 guesses that "
            "weren't supported by evidence; adds techniques discovered "
            "during investigation."
        ),
    )
    summary: str = Field(
        ...,
        min_length=1,
        description="Analyst-readable 2-4 sentence summary of what happened.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Bullet list of key findings — SPL queries run, entities pivoted, "
            "log lines that drove the verdict. Cited in the audit trail."
        ),
    )
    reasoning: str = Field(
        ...,
        min_length=1,
        description="Chain of reasoning from evidence → verdict.",
    )

    model_config = ConfigDict(extra="forbid")


__all__ = [
    "MAX_TOOL_CALLS",
    "InvestigationOutput",
    "InvestigationState",
    "Verdict",
]
