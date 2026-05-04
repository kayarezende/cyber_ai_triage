"""Cluster E MED-4: InvestigationOutput.mitre_techniques drops malformed codes.

Pre-cluster-E behaviour: per-element ``Field(pattern=...)`` raised
ValidationError on any malformed code, which the LLM router buckets as
``validation_fail`` → schema-retry burns ~1 LLM call. New behaviour: drop
malformed codes silently, log a warning, return the valid subset. De-dupes
preserving order.
"""

from __future__ import annotations

from sentient_common.schemas.investigation import InvestigationOutput


def _base(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "verdict": "true_positive",
        "confidence": 80,
        "severity": "high",
        "summary": "summary",
        "evidence": ["e1"],
        "reasoning": "r",
        "mitre_techniques": [],
    }
    base.update(overrides)
    return base


def test_valid_codes_pass_through() -> None:
    out = InvestigationOutput.model_validate(_base(mitre_techniques=["T1059", "T1059.001"]))
    assert out.mitre_techniques == ["T1059", "T1059.001"]


def test_malformed_codes_dropped() -> None:
    out = InvestigationOutput.model_validate(
        _base(
            mitre_techniques=[
                "T1059",
                "T1059.001",
                "garbage",
                "DROP TABLE",
                " T1003 ",
                "",
            ]
        )
    )
    assert out.mitre_techniques == ["T1059", "T1059.001"]


def test_dedupes_preserving_order() -> None:
    out = InvestigationOutput.model_validate(
        _base(mitre_techniques=["T1059", "T1003", "T1059", "T1059.001", "T1003"])
    )
    assert out.mitre_techniques == ["T1059", "T1003", "T1059.001"]


def test_empty_default_unchanged() -> None:
    out = InvestigationOutput.model_validate(_base(mitre_techniques=[]))
    assert out.mitre_techniques == []


def test_all_malformed_returns_empty() -> None:
    out = InvestigationOutput.model_validate(
        _base(mitre_techniques=["bogus", "also-bad", "T-not-a-code"])
    )
    assert out.mitre_techniques == []


def test_whitespace_padded_codes_dropped() -> None:
    """LLM occasionally returns ' T1059 ' or 'T1059;' — strict regex rejects both."""
    out = InvestigationOutput.model_validate(
        _base(
            mitre_techniques=["T1059", " T1059 ", "T1003;", "\tT1059.001"],
        )
    )
    assert out.mitre_techniques == ["T1059"]


def test_subtechnique_codes_supported() -> None:
    out = InvestigationOutput.model_validate(
        _base(mitre_techniques=["T1059.001", "T1059.002", "T1059.003"])
    )
    assert out.mitre_techniques == ["T1059.001", "T1059.002", "T1059.003"]
