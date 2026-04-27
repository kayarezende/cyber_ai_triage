"""Pydantic models for the wk-8 `siem_hec_post` tool.

Posts an OCSF Detection Finding event to Splunk's HTTP Event Collector. The
event payload is the dict form (ready for JSON serialisation) — the
orchestrator builds it via `DetectionFinding.to_hec_dict()` and tacks on
Sentient verdict fields.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SiemHecPostInput(BaseModel):
    """Input contract for `siem_hec_post`."""

    event: dict[str, Any] = Field(
        ...,
        description=(
            "OCSF Detection Finding HEC dict. Caller is responsible for "
            "namespacing Sentient extension fields with `sentient_*`."
        ),
    )
    sourcetype: str | None = Field(
        default="sentient:detection_finding",
        max_length=128,
        description="Splunk sourcetype. Default mirrors the OCSF schema choice.",
    )
    index: str | None = Field(
        default="triage_verdicts",
        max_length=128,
        description=(
            "Splunk index to post to. Default `triage_verdicts` per CLAUDE.md "
            "writeback contract."
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("event")
    @classmethod
    def _non_empty(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            msg = "event payload is empty"
            raise ValueError(msg)
        return value


class SiemHecPostOutput(BaseModel):
    """Result contract."""

    success: bool
    status_code: int | None = None
    response_text: str | None = Field(default=None, max_length=2048)
    notes: str | None = None

    model_config = ConfigDict()
