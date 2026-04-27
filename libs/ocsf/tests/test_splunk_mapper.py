"""Tests for the Splunk-notable -> OCSF Detection Finding mapper.

Covers:
* `urgency` -> `SeverityId` mapping (case-insensitive + fallback).
* `annotations.mitre_attack` extraction across list / comma-string / polluted shapes.
* 12 hand-authored Splunk notable variants (one per realistic ES alert shape).
* 3 negative paths (`_time` missing, `_time` garbage, IP garbage).
* 1 round-trip via `validate_detection_finding` -- proves wire format stability.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from sentient_ocsf import (
    DetectionFinding,
    SeverityId,
    SplunkNotable,
    map_notable_to_ocsf,
    validate_detection_finding,
)

LoadNotable = Callable[[str], dict[str, Any]]


def _map(notable: dict[str, Any], **kwargs: Any) -> DetectionFinding:
    """Convenience wrapper -- passes a stable finding_uid for assertions."""
    return map_notable_to_ocsf(notable, finding_uid="inc-test-uuid", **kwargs)


class TestSeverityMapping:
    @pytest.mark.parametrize(
        ("urgency", "expected"),
        [
            ("informational", SeverityId.INFORMATIONAL),
            ("INFO", SeverityId.INFORMATIONAL),
            ("Low", SeverityId.LOW),
            ("medium", SeverityId.MEDIUM),
            ("med", SeverityId.MEDIUM),
            ("HIGH", SeverityId.HIGH),
            ("critical", SeverityId.CRITICAL),
            ("  Critical  ", SeverityId.CRITICAL),
        ],
    )
    def test_known_urgencies_map(
        self,
        urgency: str,
        expected: SeverityId,
        load_notable: LoadNotable,
    ) -> None:
        notable = load_notable("degraded_minimal")
        notable["urgency"] = urgency
        finding = _map(notable)
        assert finding.severity_id == expected

    @pytest.mark.parametrize("urgency", ["bogus", "", "definitely-not-a-real-level"])
    def test_unknown_urgency_falls_back(
        self,
        urgency: str,
        load_notable: LoadNotable,
    ) -> None:
        notable = load_notable("degraded_minimal")
        notable["urgency"] = urgency
        finding = _map(notable)
        assert finding.severity_id == SeverityId.UNKNOWN

    def test_missing_urgency_falls_back(self, load_notable: LoadNotable) -> None:
        notable = load_notable("degraded_minimal")
        notable.pop("urgency", None)
        finding = _map(notable)
        assert finding.severity_id == SeverityId.UNKNOWN


class TestTechniqueExtraction:
    def _make_notable(
        self,
        load_notable: LoadNotable,
        mitre_attack: Any,
    ) -> dict[str, Any]:
        notable = load_notable("degraded_minimal")
        notable["annotations"] = {"mitre_attack": mitre_attack}
        return notable

    def test_list_shape(self, load_notable: LoadNotable) -> None:
        notable = self._make_notable(load_notable, ["T1059", "T1071.004"])
        finding = _map(notable)
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1059", "T1071.004"]
        assert finding.mitre_techniques == codes

    def test_comma_string_shape(self, load_notable: LoadNotable) -> None:
        notable = self._make_notable(load_notable, "T1566.002,T1566.001")
        finding = _map(notable)
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1566.002", "T1566.001"]

    def test_dedup_preserves_first_seen(self, load_notable: LoadNotable) -> None:
        notable = self._make_notable(load_notable, ["T1059", "T1059", "T1059.001"])
        finding = _map(notable)
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1059", "T1059.001"]

    def test_non_tcode_filtered(self, load_notable: LoadNotable) -> None:
        # "foo" starts with a letter so MitreTechnique would accept it; the
        # mapper's T-code regex must drop it BEFORE that.
        notable = self._make_notable(load_notable, ["foo", "T1059"])
        finding = _map(notable)
        assert [a.technique.uid for a in finding.attacks] == ["T1059"]

    def test_tactic_code_filtered(self, load_notable: LoadNotable) -> None:
        # OCSF distinguishes tactic vs technique. Tactic codes (TAxxxx) must
        # NOT leak into the technique field.
        notable = self._make_notable(load_notable, ["TA0002", "T1059"])
        finding = _map(notable)
        assert [a.technique.uid for a in finding.attacks] == ["T1059"]

    def test_sub_technique_passthrough(self, load_notable: LoadNotable) -> None:
        notable = self._make_notable(load_notable, ["T1059.001"])
        finding = _map(notable)
        assert finding.attacks[0].technique.uid == "T1059.001"

    def test_empty_when_missing(self, load_notable: LoadNotable) -> None:
        notable = load_notable("degraded_minimal")
        finding = _map(notable)
        assert finding.attacks == []
        assert finding.mitre_techniques == []


class TestNotableVariants:
    @pytest.mark.parametrize(
        "fixture",
        [
            "auth_success_windows",
            "auth_failure_brute_force",
            "endpoint_malware_hash",
            "endpoint_powershell_4104",
            "network_dns_tunnel",
            "network_no_actor",
            "proxy_c2_beacon",
            "cloud_aws_iam",
            "dlp_data_exfil",
            "email_phish",
            "degraded_minimal",
            "malformed_urgency",
        ],
    )
    def test_variant_validates(
        self,
        fixture: str,
        load_notable: LoadNotable,
    ) -> None:
        finding = _map(load_notable(fixture))
        assert finding.class_uid == 2004
        assert finding.finding_info.uid == "inc-test-uuid"
        assert finding.metadata.uid == "inc-test-uuid"
        assert finding.metadata.log_provider == "splunk"

    def test_auth_success_full_surface(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("auth_success_windows"))
        assert finding.severity_id == SeverityId.INFORMATIONAL
        assert finding.actor is not None
        assert finding.actor.user is not None
        assert finding.actor.user.name == "CORP\\alice"
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "10.0.5.42"
        assert finding.src_endpoint.hostname == "wks-alice-01"
        assert finding.dst_endpoint is not None
        assert finding.dst_endpoint.ip == "10.0.0.10"
        assert finding.dst_endpoint.port == 445
        assert [a.technique.uid for a in finding.attacks] == ["T1078"]

    def test_auth_failure_no_user(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("auth_failure_brute_force"))
        assert finding.severity_id == SeverityId.MEDIUM
        assert finding.actor is None
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "203.0.113.55"
        assert [a.technique.uid for a in finding.attacks] == ["T1110", "T1110.001"]

    def test_endpoint_malware_hash_extracted_fields(
        self,
        load_notable: LoadNotable,
    ) -> None:
        finding = _map(load_notable("endpoint_malware_hash"))
        assert finding.severity_id == SeverityId.HIGH
        assert finding.actor is not None
        assert finding.actor.user is not None
        assert finding.actor.user.name == "CORP\\bob"
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "10.0.5.88"
        assert finding.src_endpoint.hostname == "wks-bob-04"
        assert finding.dst_endpoint is None
        assert [a.technique.uid for a in finding.attacks] == [
            "T1566.001",
            "T1204.002",
        ]

    def test_powershell_techniques(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("endpoint_powershell_4104"))
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1059.001", "T1105"]

    def test_dns_tunnel_dest_port(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("network_dns_tunnel"))
        assert finding.dst_endpoint is not None
        assert finding.dst_endpoint.port == 53

    def test_network_no_actor(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("network_no_actor"))
        assert finding.actor is None
        assert finding.dst_endpoint is None
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "198.51.100.77"

    def test_proxy_dest_hostname_only(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("proxy_c2_beacon"))
        assert finding.dst_endpoint is not None
        assert finding.dst_endpoint.ip is None
        assert finding.dst_endpoint.hostname == "api.evil.example"

    def test_cloud_aws_iam_ipv6_and_arn(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("cloud_aws_iam"))
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "2001:db8:abcd::1"
        assert finding.actor is not None
        assert finding.actor.user is not None
        assert finding.actor.user.name == "arn:aws:iam::123456789012:user/svc-deploy"

    def test_dlp_critical_three_techniques(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("dlp_data_exfil"))
        assert finding.severity_id == SeverityId.CRITICAL
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1041", "T1071", "T1567.002"]

    def test_email_phish_actor_is_sender(self, load_notable: LoadNotable) -> None:
        # Two-user shape: src_user (sender) is the actor; user (recipient)
        # is the target. The OCSF actor must be the sender.
        finding = _map(load_notable("email_phish"))
        assert finding.actor is not None
        assert finding.actor.user is not None
        assert finding.actor.user.name == "billing@payro1l-update.example"
        # comma-separated technique string
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1566.002", "T1566.001"]

    def test_degraded_minimal_only_required(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("degraded_minimal"))
        assert finding.severity_id == SeverityId.LOW
        assert finding.actor is None
        assert finding.src_endpoint is None
        assert finding.dst_endpoint is None
        assert finding.attacks == []
        assert finding.finding_info.title == "Custom - Tenant Adhoc Saved Search - Rule"

    def test_malformed_urgency_filters_techniques(
        self,
        load_notable: LoadNotable,
    ) -> None:
        finding = _map(load_notable("malformed_urgency"))
        assert finding.severity_id == SeverityId.UNKNOWN
        # TA0002 (tactic) + foo (free text) dropped; T1059 + T1059.003 kept.
        codes = [a.technique.uid for a in finding.attacks]
        assert codes == ["T1059", "T1059.003"]


class TestNegativePaths:
    def test_missing_time_raises(self, load_notable: LoadNotable) -> None:
        notable = load_notable("degraded_minimal")
        notable.pop("_time", None)
        with pytest.raises(ValidationError):
            _map(notable)

    def test_garbage_time_raises(self, load_notable: LoadNotable) -> None:
        notable = load_notable("degraded_minimal")
        notable["_time"] = "yesterday"
        with pytest.raises(ValueError, match="unparseable Splunk _time"):
            _map(notable)

    def test_garbage_ip_raises(self, load_notable: LoadNotable) -> None:
        notable = load_notable("auth_success_windows")
        notable["src_ip"] = "999.999.999.999"
        with pytest.raises(ValidationError):
            _map(notable)


class TestRoundTrip:
    def test_model_dump_revalidates(self, load_notable: LoadNotable) -> None:
        finding = _map(load_notable("dlp_data_exfil"))
        raw = finding.model_dump(mode="json", exclude_none=True)
        revalidated = validate_detection_finding(raw)
        assert revalidated.severity_id == SeverityId.CRITICAL
        assert [a.technique.uid for a in revalidated.attacks] == [
            a.technique.uid for a in finding.attacks
        ]
        assert revalidated.actor is not None
        assert revalidated.actor.user is not None
        assert revalidated.actor.user.name == "CORP\\dave"

    def test_iso8601_time_input(self, load_notable: LoadNotable) -> None:
        # Splunk occasionally emits ISO-8601 instead of epoch seconds.
        notable = load_notable("degraded_minimal")
        notable["_time"] = "2025-04-27T23:00:00+00:00"
        finding = _map(notable)
        assert finding.time == 1745794800000

    def test_iso8601_z_suffix(self, load_notable: LoadNotable) -> None:
        notable = load_notable("degraded_minimal")
        notable["_time"] = "2025-04-27T23:00:00Z"
        finding = _map(notable)
        assert finding.time == 1745794800000

    def test_splunk_notable_model_input_accepted(
        self,
        load_notable: LoadNotable,
    ) -> None:
        # The mapper must also accept a pre-built SplunkNotable, not just dict.
        raw = load_notable("auth_success_windows")
        pre_built = SplunkNotable.model_validate(raw)
        finding = map_notable_to_ocsf(pre_built, finding_uid="inc-pre-built")
        assert finding.finding_info.uid == "inc-pre-built"

    def test_received_at_ms_overrides_default(
        self,
        load_notable: LoadNotable,
    ) -> None:
        finding = map_notable_to_ocsf(
            load_notable("degraded_minimal"),
            finding_uid="inc-x",
            received_at_ms=12345,
        )
        assert finding.finding_info.created_time == 12345

    def test_to_hec_dict_preserves_actor_and_endpoints(
        self,
        load_notable: LoadNotable,
    ) -> None:
        finding = _map(load_notable("auth_success_windows"))
        hec = finding.to_hec_dict()
        # OCSF-spec sub-models appear at top level, NOT namespaced.
        assert hec["actor"]["user"]["name"] == "CORP\\alice"
        assert hec["src_endpoint"]["ip"] == "10.0.5.42"
        assert hec["dst_endpoint"]["port"] == 445
        # Sentient extensions still namespaced via to_hec_dict()'s rename pass.
        assert "sentient_mitre_techniques" in hec
        assert "mitre_techniques" not in hec
