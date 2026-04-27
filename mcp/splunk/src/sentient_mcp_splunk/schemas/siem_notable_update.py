"""Pydantic models for the wk-8 `siem_notable_update` tool.

Posts an analyst-visible comment + (optionally) status / urgency override to a
Splunk Enterprise Security notable event. ES only; on plain Splunk Enterprise
(no `index=notable`) the tool returns `degraded=true` so the agent can ship
the verdict via HEC alone. See ADR-0018.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentient_mcp_splunk.schemas.siem_get_notable import NOTABLE_ID_PATTERN


class SiemNotableUpdateInput(BaseModel):
    """Input contract for `siem_notable_update`."""

    notable_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        pattern=NOTABLE_ID_PATTERN,
        description=(
            "Notable event ID — same opaque token shape used by "
            "`siem_get_notable`. Pattern guards against SPL injection."
        ),
    )
    comment: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description=(
            "Analyst-visible comment to attach to the notable. The "
            "orchestrator typically renders the verdict + confidence + "
            "MITRE techniques + summary into this field."
        ),
    )
    status: (
        Literal["new", "in_progress", "pending", "resolved", "closed"] | None
    ) = Field(
        default=None,
        description=(
            "Optional Splunk ES notable status override. Default: leave the "
            "current ES status unchanged."
        ),
    )
    urgency: (
        Literal["informational", "low", "medium", "high", "critical"] | None
    ) = Field(
        default=None,
        description="Optional Splunk ES notable urgency override.",
    )

    model_config = ConfigDict(extra="forbid")


class SiemNotableUpdateOutput(BaseModel):
    """Result contract.

    `degraded=true` means Splunk ES is not installed; the call is a no-op and
    the caller should fall back to HEC-only writeback. Not a tool error.
    """

    notable_id: str
    success: bool
    degraded: bool = Field(
        ...,
        description=(
            "True when the Splunk instance lacks `index=notable` (plain "
            "Splunk Enterprise without ES). Caller should still HEC-post."
        ),
    )
    splunk_response: dict[str, Any] | None = None
    notes: str | None = None

    model_config = ConfigDict()
