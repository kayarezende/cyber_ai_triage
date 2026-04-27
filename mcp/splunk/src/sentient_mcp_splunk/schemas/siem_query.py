"""Pydantic models for the `siem_query` tool.

Input rejects forbidden side-effecting SPL commands (`outputlookup`,
`outputcsv`, `collect`, `sendalert`, `script`, `delete`, `rest method=POST`)
to keep the agent's tool surface read-only. Write tools land wk 8 with
`siem_notable_update` + `siem_hec_post`.

Output normalises Splunk's stringly-typed event dict into a Pydantic shape:
the canonical event fields (`_raw`, `_time`, `sourcetype`, `source`, `host`,
`index`) are first-class, everything else flows through `fields: dict`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Read-only contract for the agent's SPL surface.
#
# Splunk's SPL pipeline accepts arbitrary horizontal whitespace (spaces, tabs,
# newlines) between `|` and the command name. A token-list with `"| outputlookup"`
# variants misses `|\toutputlookup`, `|  outputlookup`, etc. Use a regex pinned
# to `\b` boundaries so `outputlookups` (a hypothetical safe extension) wouldn't
# false-positive while `| outputlookup append=true` still trips.
FORBIDDEN_SPL_COMMANDS: tuple[str, ...] = (
    "outputlookup",
    "outputcsv",
    "collect",
    "sendalert",
    "script",
    "delete",
)
_FORBIDDEN_BARE = re.compile(
    r"\|\s*(" + "|".join(FORBIDDEN_SPL_COMMANDS) + r")\b",
    flags=re.IGNORECASE,
)
# `rest` is conditionally forbidden — only when called with `method=POST` (or
# any other write-shaped variant). Pure `| rest /services/...` reads are fine
# but we don't allow them in wk-2 because the safe surface is small.
_FORBIDDEN_REST_POST = re.compile(
    r"\|\s*rest\b[^|]*method\s*=\s*post",
    flags=re.IGNORECASE,
)


class SiemQueryInput(BaseModel):
    """Input contract for `siem_query`. Validated by FastMCP at call boundary."""

    spl: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Splunk SPL search. `search` keyword auto-prepended when missing.",
    )
    earliest: str = Field(
        "-24h",
        description="Splunk time modifier or epoch (e.g. `-24h`, `-7d`, `1700000000`).",
    )
    latest: str = Field("now", description="Splunk time modifier; `now` is the default.")
    max_count: int = Field(
        100,
        ge=1,
        le=1000,
        description="Cap on returned events. Hitting the cap sets `truncated=true`.",
    )
    timeout_seconds: int = Field(
        30,
        ge=1,
        le=120,
        description="Wall-clock budget for the search. Exceed → MCP search_timeout.",
    )

    @field_validator("spl")
    @classmethod
    def _no_forbidden(cls, v: str) -> str:
        m = _FORBIDDEN_BARE.search(v)
        if m:
            msg = f"forbidden SPL command: {m.group(1).lower()}"
            raise ValueError(msg)
        if _FORBIDDEN_REST_POST.search(v):
            msg = "forbidden SPL command: rest method=POST"
            raise ValueError(msg)
        return v


class SiemEvent(BaseModel):
    """Normalised Splunk event row.

    `populate_by_name=True` so we can construct from JSON results that use the
    Splunk `_raw`/`_time` field names directly. Everything not in the canonical
    set goes into `fields` so downstream OCSF mapping (wk 3) has the full row.
    """

    raw: str = Field(default="", alias="_raw")
    time: datetime | None = Field(default=None, alias="_time")
    sourcetype: str | None = None
    source: str | None = None
    host: str | None = None
    index: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)

    @field_validator("time", mode="before")
    @classmethod
    def _parse_time(cls, v: Any) -> Any:
        # Splunk returns `_time` as ISO-8601 string or epoch float; rare runs
        # surface non-parseable strings (e.g. `__mv__time`). Swallow parse
        # errors → None rather than failing the whole event.
        if v in (None, "", "N/A"):
            return None
        return v


class SiemQueryOutput(BaseModel):
    """Result contract for `siem_query`. Stable across Splunk versions."""

    events: list[SiemEvent]
    truncated: bool
    duration_ms: int
    spl_executed: str
