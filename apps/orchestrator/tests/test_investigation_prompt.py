"""Tier-2 investigation prompt-builder tests."""

from __future__ import annotations

import json
from pathlib import Path

from sentient_ocsf.splunk_mapper import map_notable_to_ocsf
from sentient_orchestrator.investigation.prompt import (
    build_initial_user_message,
    build_system_prompt,
)

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
    return map_notable_to_ocsf(payload, finding_uid="test-finding-tier2")


# ---------------------------------------------------------------- system prompt


def test_system_prompt_includes_methodology_phases() -> None:
    sp = build_system_prompt({})
    for phase in ("Plan", "Pivot", "Correlate", "Conclude", "Cite"):
        assert phase in sp


def test_system_prompt_lists_tools() -> None:
    sp = build_system_prompt({})
    assert "siem_query" in sp
    assert "siem_get_notable" in sp


def test_system_prompt_lists_forbidden_spl_tokens() -> None:
    sp = build_system_prompt({})
    for token in ("outputlookup", "collect", "delete"):
        assert token in sp


def test_system_prompt_includes_output_contract() -> None:
    sp = build_system_prompt({})
    for verdict in ("true_positive", "false_positive", "benign", "inconclusive"):
        assert verdict in sp
    for severity in ("info", "low", "medium", "high", "critical"):
        assert severity in sp


def test_system_prompt_includes_trust_boundary() -> None:
    sp = build_system_prompt({})
    assert "untrusted" in sp.lower()


def test_system_prompt_injects_mitre_descriptions() -> None:
    sp = build_system_prompt(
        {
            "T1059.001": "PowerShell — adversary uses PowerShell.",
            "T1071": "Application Layer Protocol — C2 over standard protocols.",
        }
    )
    assert "T1059.001" in sp
    assert "PowerShell — adversary uses PowerShell" in sp
    assert "T1071" in sp


def test_system_prompt_default_when_no_mitre() -> None:
    sp = build_system_prompt({})
    assert "Tier-1 did not flag" in sp


def test_system_prompt_mitre_block_strips_control_chars() -> None:
    """MITRE descriptions sanitized as defence-in-depth."""
    sp = build_system_prompt({"T1059": "powershell\x00malicious"})
    assert "powershellmalicious" in sp
    assert "\x00" not in sp


# ---------------------------------------------------------------- user message


def test_user_message_includes_incident_title_and_severity() -> None:
    finding = _load_finding("auth_failure_brute_force.json")
    msg = build_initial_user_message(
        finding=finding,  # type: ignore[arg-type]
        triage_ctx={
            "severity": "high",
            "confidence": 80,
            "mitre_guesses": ["T1110"],
            "entities": ["203.0.113.55"],
            "reasoning": "Repeated auth failures.",
        },
        mitre_descs={"T1110": "Brute Force"},
    )
    assert "# Incident" in msg
    assert "# Tier-1 triage hand-off" in msg
    assert "203.0.113.55" in msg
    assert "T1110" in msg
    assert "Severity: high" in msg
    assert "Confidence: 80" in msg
    assert "Repeated auth failures." in msg


def test_user_message_renders_endpoints() -> None:
    finding = _load_finding("network_dns_tunnel.json")
    msg = build_initial_user_message(
        finding=finding,  # type: ignore[arg-type]
        triage_ctx={
            "severity": "medium",
            "confidence": 60,
            "mitre_guesses": [],
            "entities": [],
            "reasoning": "DNS tunnel candidate.",
        },
        mitre_descs={},
    )
    assert "ns.evil.example" in msg
    assert ":53" in msg
    # No MITRE guesses → '(none)' marker.
    assert "MITRE guesses: (none)" in msg


def test_user_message_handles_empty_triage_ctx() -> None:
    finding = _load_finding("auth_success_windows.json")
    msg = build_initial_user_message(
        finding=finding,  # type: ignore[arg-type]
        triage_ctx={
            "severity": "info",
            "confidence": 0,
            "mitre_guesses": [],
            "entities": [],
            "reasoning": "",
        },
        mitre_descs={},
    )
    assert "Entities to investigate: (none)" in msg
    assert "MITRE guesses: (none)" in msg


def test_user_message_sanitizes_actor_name() -> None:
    """Actor name from Splunk passes through sanitizer."""
    notable = {
        "search_name": "Test - Actor sanitize",
        "urgency": "low",
        "_time": "1700000000.000",
        "user": "alice\x00admin",
    }
    finding = map_notable_to_ocsf(notable, finding_uid="fid-actor")
    msg = build_initial_user_message(
        finding=finding,
        triage_ctx={
            "severity": "low",
            "confidence": 30,
            "mitre_guesses": [],
            "entities": [],
            "reasoning": "",
        },
        mitre_descs={},
    )
    assert "aliceadmin" in msg
    assert "alice\x00admin" not in msg


def test_user_message_includes_ending_directive() -> None:
    finding = _load_finding("auth_failure_brute_force.json")
    msg = build_initial_user_message(
        finding=finding,  # type: ignore[arg-type]
        triage_ctx={
            "severity": "high",
            "confidence": 80,
            "mitre_guesses": [],
            "entities": [],
            "reasoning": "x",
        },
        mitre_descs={},
    )
    assert "Begin the investigation" in msg
