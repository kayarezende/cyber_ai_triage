"""Tier-1 + Tier-2 verdict schemas, shared between orchestrator + API.

Lives in `libs/common` so the API can serialize verdicts without importing
`sentient_orchestrator` (which drags LangGraph + LangChain into the API
container). The orchestrator re-exports these from `investigation.state` and
`triage.schemas` so existing call sites are unchanged.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.functional_validators import AfterValidator

from sentient_common.logging import get_logger

log = get_logger(__name__)

#: MITRE ATT&CK technique-code shape: `T<digits>` with optional sub-technique
#: `.<digits>`. Used by the AfterValidator below + the post-pass detection
#: rule engine.
_MITRE_CODE_RE = re.compile(r"^T\d+(\.\d+)?$")


def validate_mitre_codes(values: list[str]) -> list[str]:
    """Drop malformed T-codes + de-dupe preserving order; warn on drops.

    Cluster E MED-4: the LLM occasionally returns shapes like
    ``"T1059.001;"``, ``" T1059"``, or empty strings. Per-element
    ``Field(pattern=...)`` would raise ValidationError — the router then
    buckets the whole call as ``validation_fail`` and burns a schema-retry
    on a recoverable issue. Drop bad codes silently, surface them in a
    structured warning, return the valid subset.
    """
    if not values:
        return []
    seen: set[str] = set()
    kept: list[str] = []
    dropped: list[str] = []
    for raw in values:
        if not isinstance(raw, str):
            dropped.append(repr(raw))
            continue
        if not _MITRE_CODE_RE.match(raw):
            dropped.append(raw)
            continue
        if raw in seen:
            continue
        seen.add(raw)
        kept.append(raw)
    if dropped:
        log.warning(
            "mitre_techniques contained malformed codes; dropped",
            dropped=dropped[:20],
            kept=kept,
        )
    return kept


Severity = Literal["info", "low", "medium", "high", "critical"]

Verdict = Literal["true_positive", "false_positive", "benign", "inconclusive"]

ReviewStatus = Literal["approved", "flagged", "skipped"]
HallucinationRisk = Literal["low", "medium", "high"]
ConfidenceAssessment = Literal["overconfident", "well_calibrated", "underconfident"]


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
    mitre_techniques: Annotated[list[str], AfterValidator(validate_mitre_codes)] = Field(
        default_factory=list,
        description=(
            "Refined MITRE technique list. Removes Tier-1 guesses that "
            "weren't supported by evidence; adds techniques discovered "
            "during investigation. MED-4: malformed codes from the LLM "
            "are dropped + warning-logged, not raised — partial output "
            "is preferable to burning a schema-retry."
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
        description=("Likelihood that the draft cites unverified or fabricated evidence."),
    )
    confidence_assessment: ConfidenceAssessment = Field(
        ...,
        description=(
            "Whether the draft's confidence is calibrated relative to the " "evidence cited."
        ),
    )
    notes: str = Field(..., min_length=1, description="1-3 sentence critic notes.")
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
    "validate_mitre_codes",
]
