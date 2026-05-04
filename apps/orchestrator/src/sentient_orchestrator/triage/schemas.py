"""Tier-1 triage Pydantic output schema.

Severity literal mirrors `investigations.severity` enum (5-value set;
`unknown` + `fatal` from OCSF's wider scale are excluded — the agent always
picks a confident severity).

`Severity` lives in `sentient_common.schemas.investigation` so the API +
frontend can share it without pulling the orchestrator deps. Re-exported
here for existing import sites.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field
from pydantic.functional_validators import AfterValidator

from sentient_common.schemas.investigation import Severity, validate_mitre_codes


class TriageOutput(BaseModel):
    """Tier-1 verdict surface produced by the triage LLM call."""

    severity: Severity = Field(
        ...,
        description=(
            "Confident severity. `info`/`low` auto-close benign; " "`medium`+ escalates to Tier-2."
        ),
    )
    confidence: Annotated[int, Field(ge=0, le=100)] = Field(
        ...,
        description=(
            "0-100 integer confidence. >=80 strong, 50-79 plausible, " "<50 weak/ambiguous."
        ),
    )
    # Drop-and-warn rather than strict-fail (matches Tier-2's
    # `InvestigationOutput.mitre_techniques`, cluster E MED-4). Per-element
    # `Field(pattern=...)` would raise on the LLM's most common shapes of
    # malformed output (`"T1059.x"`, `" T1059;"`, empty strings) → router
    # buckets the whole triage call as `validation_fail` → schema-retry
    # burns ~1 LLM call → if both retries fail, fallback-exhausted marks
    # the investigation inconclusive even though severity + reasoning were
    # perfectly usable. The valid-subset path keeps the verdict shipping.
    mitre_guesses: Annotated[list[str], AfterValidator(validate_mitre_codes)] = Field(
        default_factory=list,
        description=(
            "MITRE ATT&CK technique IDs the agent suspects (e.g. `T1059.001`). "
            "Empty list when no technique applies. Malformed codes are "
            "dropped with a structured warning rather than rejecting the "
            "whole triage payload."
        ),
    )
    entities_to_investigate: list[str] = Field(
        default_factory=list,
        description=(
            "Hostnames, IPs, usernames, file hashes — anything Tier-2 should "
            "pivot on. Empty list when no entity stood out."
        ),
    )
    reasoning: str = Field(
        ...,
        min_length=1,
        description="Short rationale for the verdict, captured in the audit trail.",
    )

    model_config = ConfigDict(extra="forbid")


__all__ = ["Severity", "TriageOutput"]
