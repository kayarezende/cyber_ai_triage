"""Tier-1 triage Pydantic output schema.

Severity literal mirrors `investigations.severity` enum (5-value set;
`unknown` + `fatal` from OCSF's wider scale are excluded — the agent always
picks a confident severity).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class TriageOutput(BaseModel):
    """Tier-1 verdict surface produced by the triage LLM call."""

    severity: Severity = Field(
        ...,
        description=(
            "Confident severity. `info`/`low` auto-close benign; "
            "`medium`+ escalates to Tier-2."
        ),
    )
    confidence: Annotated[int, Field(ge=0, le=100)] = Field(
        ...,
        description=(
            "0-100 integer confidence. >=80 strong, 50-79 plausible, "
            "<50 weak/ambiguous."
        ),
    )
    mitre_guesses: list[Annotated[str, Field(pattern=r"^T\d+(\.\d+)?$")]] = Field(
        default_factory=list,
        description=(
            "MITRE ATT&CK technique IDs the agent suspects (e.g. `T1059.001`). "
            "Empty list when no technique applies."
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
