"""Tier-1 + Tier-2 verdict schemas, shared between orchestrator + API.

Lives in `libs/common` so the API can serialize verdicts without importing
`sentient_orchestrator` (which drags LangGraph + LangChain into the API
container). The orchestrator re-exports these from `investigation.state` and
`triage.schemas` so existing call sites are unchanged.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]

Verdict = Literal["true_positive", "false_positive", "benign", "inconclusive"]

ReviewStatus = Literal["approved", "flagged", "skipped"]
HallucinationRisk = Literal["low", "medium", "high"]
ConfidenceAssessment = Literal[
    "overconfident", "well_calibrated", "underconfident"
]


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


class ReviewOutput(BaseModel):
    """Wk-7. Critic surface emitted by `review_node`.

    Annotation-only — does NOT override `InvestigationOutput.confidence` or
    `verdict`. The flagged status surfaces in HITL UI (wk-8) so the analyst
    knows where to focus when approving.
    """

    status: Literal["approved", "flagged"] = Field(
        ...,
        description=(
            "`approved` — review pass found no concerns. `flagged` — at least "
            "one hallucination indicator or low-confidence reasoning."
        ),
    )
    hallucination_risk: HallucinationRisk = Field(
        ...,
        description=(
            "Likelihood that the draft cites unverified or fabricated evidence."
        ),
    )
    confidence_assessment: ConfidenceAssessment = Field(
        ...,
        description=(
            "Whether the draft's confidence is calibrated relative to the "
            "evidence cited."
        ),
    )
    notes: str = Field(
        ..., min_length=1, description="1-3 sentence critic notes."
    )
    flagged_claims: list[str] = Field(
        default_factory=list,
        description=(
            "Specific claims (quoted or paraphrased from the draft's "
            "`evidence`/`reasoning`) that the reviewer judged weak."
        ),
    )

    model_config = ConfigDict(extra="forbid")


__all__ = [
    "ConfidenceAssessment",
    "HallucinationRisk",
    "InvestigationOutput",
    "ReviewOutput",
    "ReviewStatus",
    "Severity",
    "Verdict",
]
