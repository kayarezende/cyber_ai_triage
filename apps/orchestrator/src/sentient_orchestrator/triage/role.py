"""Tier-1 triage runner — one-shot LLM call, no MCP tools.

Dispatches via `LLMRouter` (role='triage') with a Pydantic-validated output
schema. Returns the parsed `TriageOutput`. The runner (apps/orchestrator/
src/sentient_orchestrator/runner.py) consumes the output to decide
auto-close vs Tier-2 escalation.
"""

from __future__ import annotations

from uuid import UUID

from sentient_ocsf.detection_finding import DetectionFinding
from sentient_orchestrator.llm.router import LLMRouter
from sentient_orchestrator.triage.prompt import SYSTEM_PROMPT, build_user_message
from sentient_orchestrator.triage.schemas import TriageOutput


async def run_triage(
    *,
    router: LLMRouter,
    finding: DetectionFinding,
    mitre_descs: dict[str, str],
    investigation_id: UUID,
) -> TriageOutput:
    """Run Tier-1 triage; return the parsed verdict."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_message(finding, mitre_descs)},
    ]
    result = await router.call(
        role="triage",
        messages=messages,
        response_schema=TriageOutput,
        investigation_id=investigation_id,
    )
    if not isinstance(result.parsed, TriageOutput):
        msg = (
            f"router returned unexpected parsed type {type(result.parsed).__name__}; "
            "expected TriageOutput"
        )
        raise TypeError(msg)
    return result.parsed


__all__ = ["run_triage"]
