"""Hand-rolled Pydantic v2 models for OCSF 1.3.0.

Scope wk-2 spike: OCSF Detection Finding (class_uid 2004) — the writeback
shape Sentient Layer posts to Splunk HEC + (optionally) `notable_update` for
ES tenants.

ADR-0007 locks OCSF 1.3.0. ADR-0020 (added Day 5 wk 2) supersedes the
"validator implementation" choice in ADR-0007: hand-rolled here rather than
importing `py-ocsf-models` (which targets 1.5.0 → drift).

Future expansion (wk 3 mapper): full incident-side Detection Finding for
Splunk-notable normalisation. Same root class — just more fields populated.
"""

from sentient_ocsf.detection_finding import (
    OCSF_VERSION,
    Actor,
    Analytic,
    AnalyticTypeId,
    Attack,
    CategoryUid,
    ClassUid,
    DetectionFinding,
    DetectionFindingActivityId,
    Disposition,
    FindingInfo,
    Metadata,
    MitreTactic,
    MitreTechnique,
    NetworkEndpoint,
    Product,
    SeverityId,
    User,
    Verdict,
    validate_detection_finding,
)
from sentient_ocsf.splunk_mapper import SplunkNotable, map_notable_to_ocsf

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
    "SplunkNotable",
    "User",
    "Verdict",
    "map_notable_to_ocsf",
    "validate_detection_finding",
]
