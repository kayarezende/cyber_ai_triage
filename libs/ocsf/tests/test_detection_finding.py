"""Schema tests for the OCSF Detection Finding root model.

Validate construction of a realistic example, the `to_hec_dict()` Sentient
extension namespacing, and the `validate_detection_finding(payload)`
round-trip used by the wk-3 Splunk → OCSF mapper.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentient_ocsf import (
    OCSF_VERSION,
    Analytic,
    AnalyticTypeId,
    Attack,
    DetectionFinding,
    DetectionFindingActivityId,
    Disposition,
    FindingInfo,
    Metadata,
    MitreTechnique,
    Product,
    SeverityId,
    Verdict,
    validate_detection_finding,
)


def _example_detection_finding() -> DetectionFinding:
    return DetectionFinding(
        severity_id=SeverityId.HIGH,
        time=1745794800000,
        metadata=Metadata(
            product=Product(
                name="Sentient Layer",
                vendor_name="Sentient Layer",
                version="0.1.0",
            ),
            log_provider="splunk",
            uid="inv-abc123",
        ),
        finding_info=FindingInfo(
            uid="inv-abc123",
            title="Suspicious PowerShell + DNS tunnelling",
            desc=(
                "Investigation auto-correlated PowerShell 4104 events with "
                "stream:dns TXT-record bursts."
            ),
            analytic=Analytic(
                name="Sentient SOC Triage",
                type_id=AnalyticTypeId.BEHAVIORAL,
                version="0.1.0",
            ),
            created_time=1745794800000,
        ),
        confidence=82,
        disposition_id=Disposition.TRUE_POSITIVE,
        disposition="True Positive",
        attacks=[
            Attack(technique=MitreTechnique(uid="T1059.001", name="PowerShell")),
            Attack(technique=MitreTechnique(uid="T1071.004", name="DNS")),
        ],
        message="DNS-tunnel C2 over PowerShell loader. Recommend isolation.",
        verdict=Verdict.TRUE_POSITIVE,
        evidence_url="s3://evidence/inv-abc123/manifest.json",
        mitre_techniques=["T1059.001", "T1071.004"],
    )


class TestDetectionFinding:
    def test_construction_minimal(self) -> None:
        df = DetectionFinding(
            severity_id=SeverityId.LOW,
            time=1745794800000,
            metadata=Metadata(
                product=Product(name="Sentient", vendor_name="Sentient"),
            ),
            finding_info=FindingInfo(uid="x", title="benign"),
        )
        assert df.class_uid == 2004
        assert df.category_uid == 2
        assert df.activity_id == DetectionFindingActivityId.CREATE
        assert df.metadata.version == OCSF_VERSION
        assert df.attacks == []
        assert df.mitre_techniques == []

    def test_construction_full_example(self) -> None:
        df = _example_detection_finding()
        assert df.severity_id == SeverityId.HIGH
        assert len(df.attacks) == 2
        assert df.attacks[0].technique.uid == "T1059.001"
        assert df.verdict == Verdict.TRUE_POSITIVE
        assert df.confidence == 82

    def test_typeuid_default_matches(self) -> None:
        df = _example_detection_finding()
        # 2004 * 100 + 1 (Create) = 200401
        assert df.type_uid == 200401

    def test_invalid_typeuid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            DetectionFinding(
                severity_id=SeverityId.LOW,
                time=1,
                metadata=Metadata(
                    product=Product(name="x", vendor_name="x"),
                ),
                finding_info=FindingInfo(uid="x", title="x"),
                type_uid=300401,  # wrong class prefix
            )

    def test_typeuid_derived_from_non_default_activity(self) -> None:
        """`type_uid` auto-tracks `activity_id` when not explicitly supplied."""
        df = DetectionFinding(
            severity_id=SeverityId.LOW,
            time=1,
            metadata=Metadata(product=Product(name="x", vendor_name="x")),
            finding_info=FindingInfo(uid="x", title="x"),
            activity_id=DetectionFindingActivityId.UPDATE,
        )
        # 2004 * 100 + 2 (UPDATE) = 200402
        assert df.type_uid == 200402

    def test_typeuid_mismatch_with_activity_rejected(self) -> None:
        """Caller supplies BOTH activity_id and type_uid that disagree → reject."""
        with pytest.raises(ValidationError):
            DetectionFinding(
                severity_id=SeverityId.LOW,
                time=1,
                metadata=Metadata(product=Product(name="x", vendor_name="x")),
                finding_info=FindingInfo(uid="x", title="x"),
                activity_id=DetectionFindingActivityId.CREATE,
                type_uid=200402,  # would be UPDATE — mismatches CREATE
            )

    @pytest.mark.parametrize("conf", [-1, 101, 200])
    def test_confidence_bounds(self, conf: int) -> None:
        with pytest.raises(ValidationError):
            DetectionFinding(
                severity_id=SeverityId.LOW,
                time=1,
                metadata=Metadata(
                    product=Product(name="x", vendor_name="x"),
                ),
                finding_info=FindingInfo(uid="x", title="x"),
                confidence=conf,
            )

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            DetectionFinding(
                severity_id=SeverityId.LOW,
                time=1,
                metadata=Metadata(
                    product=Product(name="x", vendor_name="x"),
                ),
                finding_info=FindingInfo(uid="x", title="x"),
                weird_unknown_field=42,  # type: ignore[call-arg]
            )

    def test_technique_uid_must_start_with_letter(self) -> None:
        with pytest.raises(ValidationError):
            MitreTechnique(uid="1059.001")  # missing T prefix


class TestHecDict:
    def test_extension_fields_namespaced(self) -> None:
        df = _example_detection_finding()
        d = df.to_hec_dict()
        # Sentient extensions renamed
        assert "sentient_verdict" in d
        assert "sentient_evidence_url" in d
        assert "sentient_mitre_techniques" in d
        # Originals dropped (not just duplicated)
        assert "verdict" not in d
        assert "evidence_url" not in d
        assert "mitre_techniques" not in d

    def test_class_uid_present(self) -> None:
        df = _example_detection_finding()
        d = df.to_hec_dict()
        assert d["class_uid"] == 2004
        assert d["category_uid"] == 2
        assert d["type_uid"] == 200401

    def test_excludes_none_fields(self) -> None:
        df = DetectionFinding(
            severity_id=SeverityId.LOW,
            time=1,
            metadata=Metadata(product=Product(name="x", vendor_name="x")),
            finding_info=FindingInfo(uid="x", title="x"),
        )
        d = df.to_hec_dict()
        # Optional fields with None should not pollute the HEC payload.
        assert "confidence" not in d
        assert "disposition" not in d
        assert "message" not in d


class TestValidateDetectionFinding:
    def test_round_trip(self) -> None:
        df = _example_detection_finding()
        # serialise → deserialise via the validator entrypoint
        raw = df.model_dump(mode="json")
        df2 = validate_detection_finding(raw)
        assert df2.attacks[0].technique.uid == "T1059.001"
        assert df2.verdict == Verdict.TRUE_POSITIVE

    def test_rejects_wrong_class_uid(self) -> None:
        df = _example_detection_finding()
        raw = df.model_dump(mode="json")
        raw["class_uid"] = 9999
        with pytest.raises(ValidationError):
            validate_detection_finding(raw)
