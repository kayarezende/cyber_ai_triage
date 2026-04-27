"""Pydantic models for the `siem_get_notable` tool.

Notable events on Splunk Enterprise Security live in `index=notable`. On plain
Splunk Enterprise (founder's box) that index doesn't exist — the tool returns
`degraded=true` instead of erroring, so the agent can decide whether to drop
to HEC-only verdict workflow without a separate capability negotiation.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from sentient_mcp_splunk.schemas.siem_query import SiemEvent

NOTABLE_ID_PATTERN = r"^[A-Za-z0-9_:.\-@]+$"


class SiemGetNotableInput(BaseModel):
    """Input contract for `siem_get_notable`."""

    notable_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        pattern=NOTABLE_ID_PATTERN,
        description=(
            "Notable event ID. Splunk uses opaque tokens; the pattern guards "
            "against SPL injection."
        ),
    )


class SiemGetNotableOutput(BaseModel):
    """Result contract.

    `degraded=true` is **not** a tool error — it's a structural observation.
    The agent wraps `degraded` results into the writeback decision (HEC-only
    vs dual). See ADR-0018.
    """

    notable_id: str
    found: bool
    degraded: bool = Field(
        ...,
        description=(
            "True when the Splunk instance lacks `index=notable` (plain "
            "Splunk Enterprise without ES). On `degraded=true` the verdict "
            "still ships via HEC; only inline `notable_update` is skipped."
        ),
    )
    event: SiemEvent | None = None
    notes: str | None = None

    model_config = ConfigDict()
