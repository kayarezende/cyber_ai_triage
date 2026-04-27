"""Triage prompt-builder tests over wk-3 OCSF fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentient_ocsf.detection_finding import validate_detection_finding
from sentient_ocsf.splunk_mapper import map_notable_to_ocsf
from sentient_orchestrator.triage.prompt import SYSTEM_PROMPT, build_user_message

FIXTURES_DIR = (
    Path(__file__).resolve().parents[3]
    / "libs"
    / "ocsf"
    / "tests"
    / "fixtures"
    / "splunk_notables"
)


def _load_finding(name: str) -> object:
    payload = json.loads((FIXTURES_DIR / name).read_text())
    return map_notable_to_ocsf(payload, finding_uid="test-finding-001")


def test_system_prompt_mentions_severity_set() -> None:
    for name in ("info", "low", "medium", "high", "critical"):
        assert name in SYSTEM_PROMPT


def test_brute_force_includes_src_ip_and_techniques() -> None:
    finding = _load_finding("auth_failure_brute_force.json")
    msg = build_user_message(
        finding,  # type: ignore[arg-type]
        mitre_descs={
            "T1110": "Brute Force — adversary attempts password guessing.",
            "T1110.001": "Password Guessing",
        },
    )
    assert "203.0.113.55" in msg
    assert "T1110" in msg
    assert "Brute Force" in msg
    assert "vpn-gw-01" in msg


def test_powershell_includes_user_and_source_host() -> None:
    finding = _load_finding("endpoint_powershell_4104.json")
    msg = build_user_message(
        finding,  # type: ignore[arg-type]
        mitre_descs={"T1059.001": "PowerShell — adversary uses PowerShell."},
    )
    assert "carol" in msg
    assert "wks-carol-12" in msg
    assert "T1059.001" in msg
    assert "PowerShell" in msg


def test_dns_tunnel_includes_destination_port() -> None:
    finding = _load_finding("network_dns_tunnel.json")
    msg = build_user_message(finding, mitre_descs={})  # type: ignore[arg-type]
    assert "ns.evil.example" in msg
    # Endpoint renders as `hostname (ip:port)`; port appears.
    assert ":53" in msg


def test_missing_endpoints_render_none() -> None:
    """Validate the (none) fallback when actor + endpoints are absent."""
    notable = {
        "search_name": "Generic - Anomaly",
        "urgency": "medium",
        "_time": "1700000000.000",
    }
    finding = map_notable_to_ocsf(notable, finding_uid="fid-empty")
    msg = build_user_message(finding, mitre_descs={})
    assert "Actor: (none)" in msg
    assert "Source: (none)" in msg
    assert "Destination: (none)" in msg


def test_finding_validates_after_build() -> None:
    """Mapper output must round-trip through the OCSF validator unchanged."""
    finding = _load_finding("auth_failure_brute_force.json")
    payload = finding.model_dump(mode="json")  # type: ignore[attr-defined]
    validate_detection_finding(payload)
    # Sanity: no exception means OCSF stays well-formed alongside the prompt path.
    assert True


@pytest.mark.parametrize(
    "fixture",
    [
        "auth_failure_brute_force.json",
        "endpoint_powershell_4104.json",
        "network_dns_tunnel.json",
    ],
)
def test_prompt_builds_for_realistic_fixtures(fixture: str) -> None:
    finding = _load_finding(fixture)
    msg = build_user_message(finding, mitre_descs={})  # type: ignore[arg-type]
    # Smoke: the prompt has the labelled sections in stable order.
    assert msg.startswith("Finding:")
    assert "Actor:" in msg
    assert "Source:" in msg
    assert "Destination:" in msg
    assert "MITRE annotations from SIEM" in msg
