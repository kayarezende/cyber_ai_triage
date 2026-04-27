"""Wk-8 deterministic detection-rule engine.

Pure-Python evaluator over the `detection_rules` table (per-tenant + global).
Each rule has `required_techniques` (AND) and optional `any_techniques` (OR).
Match semantics:

    matched := all(t in mitre_techniques for t in required_techniques) AND
               (not any_techniques OR any(t in mitre_techniques for t in any_techniques))

`severity_override` raises severity to the named level if the agent's draft is
lower; never lowers (the `effective_severity` comparator is max-rank). This is
the deterministic post-pass per CLAUDE.md — keeps critical correlations
rule-based, not purely LLM-judged.

`load_enabled_rules_for_tenant` is the only I/O surface; everything else is
pure functions over dataclasses for easy unit testing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_orchestrator.triage.schemas import Severity

#: Severity comparator. Strict ordering — `info < low < medium < high < critical`.
_SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RANK_TO_SEVERITY: dict[int, Severity] = {v: k for k, v in _SEVERITY_RANK.items()}


@dataclass(frozen=True)
class DetectionRule:
    """One row out of `detection_rules`."""

    id: str
    name: str
    required_techniques: tuple[str, ...]
    any_techniques: tuple[str, ...]
    severity_override: Severity | None
    enabled: bool


@dataclass(frozen=True)
class RuleMatch:
    """One matched rule for a given investigation's MITRE technique set."""

    rule_id: str
    rule_name: str
    matched_required: tuple[str, ...]
    matched_any: tuple[str, ...]
    severity_override: Severity | None


def evaluate_rules(
    rules: list[DetectionRule],
    *,
    mitre_techniques: list[str],
) -> list[RuleMatch]:
    """Return all rules whose technique conditions are satisfied."""
    technique_set = set(mitre_techniques)
    matches: list[RuleMatch] = []
    for rule in rules:
        if not rule.enabled:
            continue
        required = set(rule.required_techniques)
        if required and not required.issubset(technique_set):
            continue
        if rule.any_techniques:
            matched_any = technique_set & set(rule.any_techniques)
            if not matched_any:
                continue
        else:
            matched_any = set()
        matches.append(
            RuleMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                matched_required=tuple(sorted(required & technique_set)),
                matched_any=tuple(sorted(matched_any)),
                severity_override=rule.severity_override,
            )
        )
    return matches


def effective_severity(
    agent_severity: Severity,
    matches: list[RuleMatch],
) -> Severity:
    """max(agent_severity, max(rule.severity_override for rule in matches))."""
    rank = _SEVERITY_RANK.get(agent_severity, 0)
    for m in matches:
        if m.severity_override is None:
            continue
        rank = max(rank, _SEVERITY_RANK.get(m.severity_override, 0))
    return _RANK_TO_SEVERITY[rank]


_LOAD_SQL = text(
    """
    SELECT id, name, required_techniques, any_techniques,
           severity_override, enabled
      FROM detection_rules
     WHERE enabled = TRUE
       AND (tenant_id IS NULL OR tenant_id = :tid)
    """
)


def load_enabled_rules_for_tenant(
    conn: Connection, tenant_id: UUID
) -> list[DetectionRule]:
    """Pull enabled rules visible to the tenant (own + global)."""
    rows = conn.execute(_LOAD_SQL, {"tid": str(tenant_id)}).all()
    out: list[DetectionRule] = []
    for row in rows:
        sev_override_raw = row[4]
        sev_override: Severity | None = (
            cast(Severity, sev_override_raw)
            if sev_override_raw in _SEVERITY_RANK
            else None
        )
        out.append(
            DetectionRule(
                id=str(row[0]),
                name=str(row[1]),
                required_techniques=tuple(row[2] or ()),
                any_techniques=tuple(row[3] or ()),
                severity_override=sev_override,
                enabled=bool(row[5]),
            )
        )
    return out


__all__ = [
    "DetectionRule",
    "RuleMatch",
    "effective_severity",
    "evaluate_rules",
    "load_enabled_rules_for_tenant",
]
