"""OCSF 1.3.0 Detection Finding (class_uid 2004) — hand-rolled Pydantic v2.

This is intentionally narrow: only the fields Sentient Layer's wk-8 writeback
populates + the spec-required scaffolding around them. The full OCSF
Detection Finding has many more optional surfaces (actor, src_endpoint,
dst_endpoint, evidences[], enrichments[], device, etc.); we add those when a
real customer requirement makes them necessary, not preemptively.

Spec reference: https://schema.ocsf.io/1.3.0/classes/detection_finding

OCSF Sentient extensions live in `unmapped` (per OCSF convention for vendor
extensions) plus a typed Sentient block at the top level — `verdict`,
`evidence_url`, `mitre_techniques` — which we expose as proper fields for
agent + UI ergonomics. The field names are namespaced via the `sentient_*`
prefix when serialised to HEC to avoid future-OCSF collision.
"""

from __future__ import annotations

import ipaddress
from enum import IntEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

OCSF_VERSION = "1.3.0"


# ---------------------------------------------------------------------------
# OCSF enumerations (subset we use; full list in the spec)
# ---------------------------------------------------------------------------


class CategoryUid(IntEnum):
    """Top-level category. We only emit Findings (uid=2)."""

    FINDINGS = 2


class ClassUid(IntEnum):
    """Class within Findings."""

    DETECTION_FINDING = 2004


class DetectionFindingActivityId(IntEnum):
    """`activity_id` enum for class 2004. `Create` covers our verdict-write."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class SeverityId(IntEnum):
    """OCSF severity scale. Mapped from agent-determined severity."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class AnalyticTypeId(IntEnum):
    """`analytic.type_id`. We're a `Behavioral` analytic (LLM + rules)."""

    UNKNOWN = 0
    RULE = 1
    BEHAVIORAL = 2
    STATISTICAL = 3
    LEARNING = 4  # ML
    FINGERPRINTING = 5
    TAGGING = 6
    KEYWORD = 7
    OTHER = 99


# ---------------------------------------------------------------------------
# Sentient Layer extensions (typed for ergonomics; namespaced on serialise)
# ---------------------------------------------------------------------------


class Verdict(IntEnum):
    """Sentient verdict — kept compatible with `disposition_id` semantics."""

    INCONCLUSIVE = 0
    TRUE_POSITIVE = 1
    FALSE_POSITIVE = 2
    BENIGN = 3


class Disposition(IntEnum):
    """OCSF `disposition_id` subset we emit. Aligns 1:1 with `Verdict`."""

    UNKNOWN = 0
    TRUE_POSITIVE = 1
    FALSE_POSITIVE = 2
    BENIGN = 3


# ---------------------------------------------------------------------------
# OCSF nested objects
# ---------------------------------------------------------------------------


class Product(BaseModel):
    """OCSF `product_t` — the analytic-emitting product."""

    name: str
    vendor_name: str
    version: str | None = None

    model_config = ConfigDict(extra="forbid")


class Metadata(BaseModel):
    """OCSF `metadata_t` — required on every event."""

    version: str = Field(default=OCSF_VERSION, description="OCSF schema version.")
    product: Product
    log_provider: str | None = Field(
        default=None,
        description="Source of the underlying telemetry (e.g. `splunk`, `sentinel`).",
    )
    original_time: str | None = Field(
        default=None,
        description="Original event time as the source emitted it (ISO-8601).",
    )
    uid: str | None = Field(
        default=None,
        description="Stable UID for de-duplication. Use the investigation_id.",
    )

    model_config = ConfigDict(extra="forbid")


class Analytic(BaseModel):
    """OCSF `analytic_t` — the analytic that produced the finding."""

    name: str
    type_id: AnalyticTypeId = AnalyticTypeId.BEHAVIORAL
    version: str | None = None
    desc: str | None = None
    uid: str | None = None

    model_config = ConfigDict(extra="forbid")


class FindingInfo(BaseModel):
    """OCSF `finding_info_t` — REQUIRED for class 2004."""

    uid: str = Field(..., description="Finding UID; use the investigation_id.")
    title: str
    desc: str | None = None
    analytic: Analytic | None = None
    created_time: int | None = Field(
        default=None,
        description="Epoch ms — when the finding object was created.",
    )

    model_config = ConfigDict(extra="forbid")


class MitreTactic(BaseModel):
    """OCSF MITRE ATT&CK `tactic_t`."""

    uid: str = Field(..., description="Tactic ID, e.g. `TA0002`.")
    name: str | None = None
    src_url: str | None = None

    model_config = ConfigDict(extra="forbid")


class MitreTechnique(BaseModel):
    """OCSF MITRE ATT&CK `technique_t`."""

    uid: str = Field(..., description="Technique ID, e.g. `T1059.001`.")
    name: str | None = None
    src_url: str | None = None

    @field_validator("uid")
    @classmethod
    def _normalize_technique_uid(cls, v: str) -> str:
        # MITRE T-codes are case-sensitive in upstream STIX; ensure upper-T.
        s = v.strip()
        if not s:
            msg = "technique uid must be non-empty"
            raise ValueError(msg)
        if not s[0].isalpha():
            msg = f"technique uid must start with a letter, got {s!r}"
            raise ValueError(msg)
        return s


class Attack(BaseModel):
    """OCSF `attack_t` — one MITRE ATT&CK technique + (optional) tactic."""

    technique: MitreTechnique
    tactic: MitreTactic | None = None
    version: str | None = Field(
        default=None,
        description="MITRE ATT&CK matrix version (e.g. `15.1`).",
    )

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Actor + endpoint sub-models (wk-3 Splunk-notable mapper surface)
# ---------------------------------------------------------------------------


class User(BaseModel):
    """OCSF `user_t` — minimum surface.

    Splunk notables typically give us a single string (bare username,
    DOMAIN\\user, UPN, ARN, email). Don't parse — store raw in `name`.
    Further sub-fields (`email_addr`, `domain`, `account`, `groups`) added
    when a real notable variant forces them.
    """

    name: str | None = None

    model_config = ConfigDict(extra="forbid")


class Actor(BaseModel):
    """OCSF `actor_t` — wk-3 surface is `user` only.

    `process` deferred to wk-6 when the investigation agent's process-tree
    enrichment lands.
    """

    user: User | None = None

    model_config = ConfigDict(extra="forbid")


class NetworkEndpoint(BaseModel):
    """OCSF `network_endpoint_t` — minimum surface (ip + hostname + port).

    `_coerce_ip` tolerates Splunk's null markers (`""`, `"-"`, `"unknown"`,
    `"null"`) and returns `None` for them. Genuine garbage IPs raise via
    `ipaddress.ip_address()` — fail loud at ingest so the analyst sees it.
    """

    ip: str | None = None
    hostname: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)

    model_config = ConfigDict(extra="forbid")

    @field_validator("ip", mode="before")
    @classmethod
    def _coerce_ip(cls, v: Any) -> Any:
        if v is None or not isinstance(v, str):
            return v
        s = v.strip()
        if s in ("", "-", "unknown", "null"):
            return None
        ipaddress.ip_address(s)
        return s


# ---------------------------------------------------------------------------
# Detection Finding root
# ---------------------------------------------------------------------------


class DetectionFinding(BaseModel):
    """OCSF Detection Finding (class_uid 2004).

    Sentient Layer extensions (`verdict`, `evidence_url`, `mitre_techniques`)
    are top-level for ergonomics; on HEC serialise they become
    `sentient_verdict` / `sentient_evidence_url` / `sentient_mitre_techniques`
    via `to_hec_dict()` to keep us forward-compatible with future OCSF.
    """

    # OCSF required core
    category_uid: Literal[CategoryUid.FINDINGS] = CategoryUid.FINDINGS
    class_uid: Literal[ClassUid.DETECTION_FINDING] = ClassUid.DETECTION_FINDING
    activity_id: DetectionFindingActivityId = DetectionFindingActivityId.CREATE
    type_uid: int | None = Field(
        default=None,
        description=(
            "`class_uid * 100 + activity_id`. Auto-derived from `activity_id` when "
            "not supplied. If supplied, must match — mismatch raises."
        ),
    )
    severity_id: SeverityId
    time: int = Field(..., description="Event time as epoch milliseconds.")
    metadata: Metadata
    finding_info: FindingInfo

    # OCSF optional — populated by us
    confidence: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="0–100 confidence score (OCSF int form; we convert from float).",
    )
    disposition_id: Disposition | None = None
    disposition: str | None = None
    attacks: list[Attack] = Field(default_factory=list)
    actor: Actor | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    message: str | None = Field(
        default=None,
        description="Short human-readable verdict summary.",
    )

    # Sentient extensions (top-level for typed access; namespaced on emit).
    verdict: Verdict | None = None
    evidence_url: str | None = Field(
        default=None,
        description="Link to MinIO evidence manifest for this investigation.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description=(
            "Denormalised list of T-codes alongside the structured `attacks[]`. "
            "Lets the agent + UI filter without walking nested objects."
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _derive_or_validate_type_uid(self) -> Self:
        """`type_uid = class_uid * 100 + activity_id` (OCSF spec).

        If the caller didn't supply `type_uid`, derive it. If they did, it
        must match — otherwise we'd silently emit inconsistent OCSF.
        """
        expected = int(ClassUid.DETECTION_FINDING) * 100 + int(self.activity_id)
        if self.type_uid is None:
            self.type_uid = expected
        elif self.type_uid != expected:
            msg = (
                f"type_uid {self.type_uid} doesn't match "
                f"class_uid {int(self.class_uid)} + activity_id "
                f"{int(self.activity_id)} (expected {expected})"
            )
            raise ValueError(msg)
        return self

    def to_hec_dict(self) -> dict[str, Any]:
        """Serialise to a dict ready for Splunk HEC (`/services/collector/event`).

        Sentient extension fields are renamed to `sentient_*` to avoid future
        OCSF collisions. Enums are serialised as their integer values.
        """
        payload = self.model_dump(exclude_none=True, mode="json")
        # Rename Sentient extension fields.
        for src, dst in (
            ("verdict", "sentient_verdict"),
            ("evidence_url", "sentient_evidence_url"),
            ("mitre_techniques", "sentient_mitre_techniques"),
        ):
            if src in payload:
                payload[dst] = payload.pop(src)
        return payload


def validate_detection_finding(payload: dict[str, Any]) -> DetectionFinding:
    """Validate an arbitrary dict against the Detection Finding schema.

    Used by the wk-3 Splunk-notable-to-OCSF mapper + by tests that want to
    assert wire format correctness without constructing the model directly.
    """
    return DetectionFinding.model_validate(payload)


__all__ = [
    "OCSF_VERSION",
    "Actor",
    "Analytic",
    "AnalyticTypeId",
    "Attack",
    "CategoryUid",
    "ClassUid",
    "DetectionFinding",
    "DetectionFindingActivityId",
    "Disposition",
    "FindingInfo",
    "Metadata",
    "MitreTactic",
    "MitreTechnique",
    "NetworkEndpoint",
    "Product",
    "SeverityId",
    "User",
    "Verdict",
    "validate_detection_finding",
]
