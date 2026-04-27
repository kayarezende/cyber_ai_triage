"""Wk-8 unit tests for the deterministic detection-rule engine."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest

from sentient_orchestrator.investigation.detection_rules import (
    DetectionRule,
    RuleMatch,
    effective_severity,
    evaluate_rules,
    load_enabled_rules_for_tenant,
)
from sentient_orchestrator.triage.schemas import Severity


def _rule(
    *,
    name: str = "r",
    required: tuple[str, ...] = (),
    any_: tuple[str, ...] = (),
    override: Severity | None = None,
    enabled: bool = True,
) -> DetectionRule:
    return DetectionRule(
        id=name,
        name=name,
        required_techniques=required,
        any_techniques=any_,
        severity_override=override,
        enabled=enabled,
    )


# --- evaluate_rules -------------------------------------------------------


def test_evaluate_rules_no_rules_no_matches() -> None:
    assert evaluate_rules([], mitre_techniques=["T1059.001"]) == []


def test_evaluate_rules_empty_techniques_no_match_when_required_present() -> None:
    rules = [_rule(required=("T1003",))]
    assert evaluate_rules(rules, mitre_techniques=[]) == []


def test_evaluate_rules_partial_required_no_match() -> None:
    rules = [_rule(required=("T1003", "T1021"))]
    assert evaluate_rules(rules, mitre_techniques=["T1003"]) == []


def test_evaluate_rules_required_only_matches_when_all_present() -> None:
    rules = [_rule(name="dump_then_lateral", required=("T1003", "T1021"))]
    matches = evaluate_rules(rules, mitre_techniques=["T1003", "T1021", "T1059"])
    assert len(matches) == 1
    assert matches[0].rule_name == "dump_then_lateral"
    assert set(matches[0].matched_required) == {"T1003", "T1021"}
    assert matches[0].matched_any == ()


def test_evaluate_rules_required_plus_any_needs_at_least_one_any() -> None:
    rules = [_rule(required=("T1059.001",), any_=("T1071", "T1567"))]
    # Required present but no any-set element
    assert evaluate_rules(rules, mitre_techniques=["T1059.001"]) == []
    # One any element matches → match
    matches = evaluate_rules(rules, mitre_techniques=["T1059.001", "T1071"])
    assert len(matches) == 1
    assert matches[0].matched_any == ("T1071",)


def test_evaluate_rules_disabled_skipped() -> None:
    rules = [_rule(required=("T1003",), enabled=False)]
    assert evaluate_rules(rules, mitre_techniques=["T1003"]) == []


def test_evaluate_rules_multiple_matches() -> None:
    rules = [
        _rule(name="ransom", required=("T1486",), override="critical"),
        _rule(name="creds", required=("T1003",), override="high"),
    ]
    matches = evaluate_rules(rules, mitre_techniques=["T1003", "T1486"])
    assert {m.rule_name for m in matches} == {"ransom", "creds"}


# --- effective_severity --------------------------------------------------


def test_effective_severity_no_matches_returns_agent() -> None:
    assert effective_severity("medium", []) == "medium"


def test_effective_severity_override_raises_only() -> None:
    high_match = RuleMatch(
        rule_id="x",
        rule_name="x",
        matched_required=("T1003",),
        matched_any=(),
        severity_override="high",
    )
    assert effective_severity("low", [high_match]) == "high"
    # Agent already higher → unchanged.
    assert effective_severity("critical", [high_match]) == "critical"


def test_effective_severity_picks_max_across_matches() -> None:
    matches = [
        RuleMatch(
            rule_id="a",
            rule_name="a",
            matched_required=("T1",),
            matched_any=(),
            severity_override="medium",
        ),
        RuleMatch(
            rule_id="b",
            rule_name="b",
            matched_required=("T2",),
            matched_any=(),
            severity_override="critical",
        ),
    ]
    assert effective_severity("low", matches) == "critical"


def test_effective_severity_match_without_override_is_inert() -> None:
    floor_match = RuleMatch(
        rule_id="floor",
        rule_name="floor",
        matched_required=("T1078",),
        matched_any=(),
        severity_override=None,
    )
    assert effective_severity("low", [floor_match]) == "low"


# --- load_enabled_rules_for_tenant + seed assertions ---------------------

# The integration-style DB tests below are skipped on a fresh CI checkout
# because they need the wk-8 seed run + a live Postgres. Marked with
# `pytest.mark.integration` (deselected by default per pyproject).


_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

_EXPECTED_SEED_RULES: dict[str, dict[str, Any]] = {
    "ransomware_kill_chain": {
        "required": {"T1059.001", "T1486"},
        "any": {"T1071", "T1071.001", "T1071.004"},
        "override": "critical",
    },
    "credential_dumping_then_lateral": {
        "required": {"T1003", "T1021"},
        "any": {"T1021.001", "T1021.002", "T1021.006"},
        "override": "critical",
    },
    "interactive_privilege_escalation": {
        "required": {"T1078", "T1068"},
        "any": set(),
        "override": "high",
    },
    "defense_evasion_clearlogs": {
        "required": {"T1070.001"},
        "any": {"T1059.001", "T1059.003"},
        "override": "high",
    },
    "cloud_iam_persistence": {
        "required": {"T1098.003"},
        "any": {"T1078.004"},
        "override": "high",
    },
    "data_exfil_over_c2": {
        "required": {"T1041"},
        "any": {"T1071", "T1567", "T1567.002"},
        "override": "critical",
    },
    "phishing_with_macro": {
        "required": {"T1566.001", "T1204.002"},
        "any": {"T1059.005"},
        "override": "high",
    },
    "living_off_the_land_proxy_chain": {
        "required": {"T1218.011"},
        "any": {"T1059.001", "T1218.005"},
        "override": "medium",
    },
    "webshell_persistence": {
        "required": {"T1505.003"},
        "any": {"T1190"},
        "override": "high",
    },
    "valid_accounts_only": {
        "required": {"T1078"},
        "any": set(),
        "override": "low",
    },
}


@pytest.mark.integration
def test_load_enabled_rules_for_tenant_returns_globals() -> None:
    """Integration: requires `seed_detection_rules.py` + live Postgres."""
    import os

    import psycopg
    from sqlalchemy import create_engine

    dsn_env = os.environ.get("DATABASE_URL", "")
    if not dsn_env or "CHANGEME" in dsn_env or "placeholder" in dsn_env:
        pytest.skip("DATABASE_URL not set to live DB")
    # Quick liveness check + global rule presence — guard against running
    # against a DB that hasn't been seeded.
    dsn_native = dsn_env.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(dsn_native) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE tenant_id IS NULL"
        )
        row = cur.fetchone()
        if row is None or int(row[0]) < len(_EXPECTED_SEED_RULES):
            pytest.skip(
                "detection_rules not seeded; run db/seeds/seed_detection_rules.py"
            )
    engine = create_engine(dsn_env)
    with engine.connect() as conn:
        rules = load_enabled_rules_for_tenant(conn, _TENANT_ID)
    by_name = {r.name: r for r in rules}
    for name, expected in _EXPECTED_SEED_RULES.items():
        assert name in by_name, f"missing seed rule: {name}"
        rule = by_name[name]
        assert set(rule.required_techniques) == expected["required"]
        assert set(rule.any_techniques) == expected["any"]
        assert rule.severity_override == expected["override"]
        assert rule.enabled is True
