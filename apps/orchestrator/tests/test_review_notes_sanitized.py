"""Cluster E HIGH-11: review notes + metadata sanitized + capped before INSERT.

The review-output dict comes from an LLM and the unsanitized + uncapped path
let attacker-controlled tool output ride into ``investigations.review_notes``
+ ``review_metadata`` JSONB. This test asserts the helper truncates notes to
1 KB, strips control chars, and walks the metadata via the bounded sanitizer.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

from sentient_orchestrator.investigation.runner import (
    _update_investigation_with_review,
)

INV = UUID("33333333-3333-3333-3333-333333333333")


class _RecConn:
    def __init__(self) -> None:
        self.params: dict[str, Any] | None = None

    def execute(self, _stmt: Any, params: dict[str, Any]) -> Any:
        self.params = params
        return MagicMock()


def test_notes_sanitized_and_capped() -> None:
    review = {
        "status": "approved",
        "notes": "ok\x00bad\x07more " + ("X" * 5000),
        "hallucination_risk": "low",
    }
    conn = _RecConn()
    _update_investigation_with_review(
        conn,  # type: ignore[arg-type]
        investigation_id=INV,
        review=review,
    )
    assert conn.params is not None
    notes = conn.params["notes"]
    assert "\x00" not in notes
    assert "\x07" not in notes
    assert len(notes) <= 1024


def test_metadata_walks_through_sanitizer() -> None:
    """5KB string nested in metadata must be truncated by walk_and_sanitize."""
    review = {
        "status": "flagged",
        "notes": "short",
        "flagged_claims": ["claim with bad\x00byte", "Y" * 6000],
    }
    conn = _RecConn()
    _update_investigation_with_review(
        conn,  # type: ignore[arg-type]
        investigation_id=INV,
        review=review,
    )
    assert conn.params is not None
    meta_text = conn.params["meta"]
    assert "\\u0000" not in meta_text
    assert "\x00" not in meta_text
    assert "[truncated]" in meta_text


def test_status_passes_through_unchanged() -> None:
    """`status` is a controlled Literal from ReviewOutput; no sanitization."""
    review = {"status": "approved", "notes": "fine"}
    conn = _RecConn()
    _update_investigation_with_review(
        conn,  # type: ignore[arg-type]
        investigation_id=INV,
        review=review,
    )
    assert conn.params is not None
    assert conn.params["status"] == "approved"


def test_missing_notes_defaults_to_empty_string() -> None:
    """No notes key → empty string, not None (matches CHECK constraint)."""
    review = {"status": "skipped"}
    conn = _RecConn()
    _update_investigation_with_review(
        conn,  # type: ignore[arg-type]
        investigation_id=INV,
        review=review,
    )
    assert conn.params is not None
    assert conn.params["notes"] == ""
