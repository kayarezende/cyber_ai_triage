"""Splunk notable -> OCSF 1.3.0 Detection Finding mapper.

Pure function. No I/O, no DB, no MinIO. Caller provides a `finding_uid`
(incident UUID at ingest); the wk-6 investigation agent overwrites it with
the investigation_id when finalising the verdict. The
`incidents.raw_payload_s3_key` DB column is a separate concern handled by
the wk-4 ingest webhook -- not on the OCSF object.

`verdict`, `disposition_id`, `evidence_url`, `confidence`, `message` are
left `None` here; they are populated by the wk-6 agent at writeback time.

T-code filtering: `MitreTechnique` only enforces non-empty + alphabetic
leading -- it does NOT filter T-codes. This mapper does that itself via
`_TCODE_RE` so tactic codes (`TA0002`) and free-text annotations (`foo`)
get silently dropped instead of constructing bogus `MitreTechnique` rows.
"""

from __future__ import annotations

import re
import time as _time_mod
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentient_ocsf.detection_finding import (
    Actor,
    Analytic,
    AnalyticTypeId,
    Attack,
    DetectionFinding,
    FindingInfo,
    Metadata,
    MitreTechnique,
    NetworkEndpoint,
    Product,
    SeverityId,
    User,
)

_TCODE_RE = re.compile(r"^T\d+(\.\d+)?$")

_PRODUCT = Product(
    name="Sentient Layer",
    vendor_name="Sentient Layer",
    version="0.0.1",
)

_URGENCY_TO_SEVERITY: dict[str, SeverityId] = {
    "informational": SeverityId.INFORMATIONAL,
    "info": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "med": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


class SplunkNotable(BaseModel):
    """Input contract -- mirrors the Splunk ES `notable` JSON shape.

    `extra="allow"` because the notable shape varies per saved search and per
    deployment; we only consume the fields below, the rest is ignored but not
    rejected. Splunk's underscore-prefixed fields (`_time`, `_raw`) are aliased
    because Pydantic v2 reserves leading underscores.
    """

    search_name: str
    urgency: str | None = None
    src: str | None = None
    src_ip: str | None = None
    dest: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    user: str | None = None
    src_user: str | None = None
    signature: str | None = None
    annotations: dict[str, Any] | None = None
    rid: str | None = None
    notable_time: float | str = Field(..., alias="_time")
    raw_event: str | None = Field(default=None, alias="_raw")

    model_config = ConfigDict(extra="allow", populate_by_name=True)


def _severity_from_urgency(urgency: str | None) -> SeverityId:
    if urgency is None:
        return SeverityId.UNKNOWN
    return _URGENCY_TO_SEVERITY.get(urgency.strip().lower(), SeverityId.UNKNOWN)


def _normalize_technique_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    return []


def _techniques_from_annotations(annotations: dict[str, Any] | None) -> list[Attack]:
    if not annotations:
        return []
    candidates = _normalize_technique_list(annotations.get("mitre_attack"))
    seen: set[str] = set()
    attacks: list[Attack] = []
    for code in candidates:
        if not _TCODE_RE.match(code) or code in seen:
            continue
        seen.add(code)
        attacks.append(Attack(technique=MitreTechnique(uid=code)))
    return attacks


def _actor_from_users(user: str | None, src_user: str | None) -> Actor | None:
    name = src_user or user
    if not name:
        return None
    return Actor(user=User(name=name))


def _endpoints_from_notable(
    notable: SplunkNotable,
) -> tuple[NetworkEndpoint | None, NetworkEndpoint | None]:
    src = _build_endpoint(ip=notable.src_ip, hostname=notable.src, port=None)
    dst = _build_endpoint(
        ip=notable.dest_ip,
        hostname=notable.dest,
        port=notable.dest_port,
    )
    return src, dst


def _build_endpoint(
    *,
    ip: str | None,
    hostname: str | None,
    port: int | None,
) -> NetworkEndpoint | None:
    endpoint = NetworkEndpoint(ip=ip, hostname=hostname, port=port)
    if endpoint.ip is None and endpoint.hostname is None and endpoint.port is None:
        return None
    return endpoint


def _time_to_epoch_ms(value: float | str) -> int:
    if isinstance(value, (int, float)):
        return int(float(value) * 1000)
    s = value.strip()
    try:
        return int(float(s) * 1000)
    except ValueError:
        pass
    try:
        # ISO-8601: tolerate trailing 'Z' which fromisoformat rejects on <3.11.
        normalized = s.replace("Z", "+00:00") if s.endswith("Z") else s
        return int(datetime.fromisoformat(normalized).timestamp() * 1000)
    except ValueError as exc:
        msg = f"unparseable Splunk _time value: {value!r}"
        raise ValueError(msg) from exc


def _iso8601_from_epoch_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat()


def _title_from_notable(notable: SplunkNotable) -> str:
    if notable.search_name and notable.search_name.strip():
        return notable.search_name
    if notable.signature and notable.signature.strip():
        return notable.signature
    return "(unnamed Splunk notable)"


def _analytic_from_notable(notable: SplunkNotable) -> Analytic:
    return Analytic(
        name=notable.search_name or "(unnamed Splunk saved search)",
        type_id=AnalyticTypeId.RULE,
        uid=notable.rid,
    )


def map_notable_to_ocsf(
    notable: SplunkNotable | dict[str, Any],
    *,
    finding_uid: str,
    received_at_ms: int | None = None,
) -> DetectionFinding:
    """Map a Splunk ES notable to an OCSF 1.3.0 Detection Finding."""
    n = notable if isinstance(notable, SplunkNotable) else SplunkNotable.model_validate(notable)

    event_time_ms = _time_to_epoch_ms(n.notable_time)
    received_ms = received_at_ms if received_at_ms is not None else int(_time_mod.time() * 1000)

    src_ep, dst_ep = _endpoints_from_notable(n)
    attacks = _techniques_from_annotations(n.annotations)

    return DetectionFinding(
        severity_id=_severity_from_urgency(n.urgency),
        time=event_time_ms,
        metadata=Metadata(
            product=_PRODUCT,
            log_provider="splunk",
            original_time=_iso8601_from_epoch_ms(event_time_ms),
            uid=finding_uid,
        ),
        finding_info=FindingInfo(
            uid=finding_uid,
            title=_title_from_notable(n),
            desc=n.signature,
            analytic=_analytic_from_notable(n),
            created_time=received_ms,
        ),
        attacks=attacks,
        actor=_actor_from_users(n.user, n.src_user),
        src_endpoint=src_ep,
        dst_endpoint=dst_ep,
        mitre_techniques=[a.technique.uid for a in attacks],
    )


__all__ = [
    "SplunkNotable",
    "map_notable_to_ocsf",
]
