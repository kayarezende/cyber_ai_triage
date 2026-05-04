"""Wk-9 tests for the approvals router."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def patch_approvals(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Cluster D HIGH-13: dedup + audit insert moved into
    `runner.claim_resume_intent`. Tests patch that helper at the import
    site (`approvals.claim_resume_intent`) and stage one row per
    `responses` entry — the router's pre-flight SELECT only returns
    `(approval_status,)` now.
    """
    state: dict[str, Any] = {
        "responses": [],
        "claim_calls": [],
        "claim_raises": None,
        "enqueues": [],
        "calls": [],
    }

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            state["calls"].append((str(stmt), params or {}))
            response = state["responses"].pop(0) if state["responses"] else None
            return MagicMock(first=lambda r=response: r)

        conn.execute.side_effect = execute
        yield conn

    def fake_claim(**kwargs: Any) -> None:
        state["claim_calls"].append(kwargs)
        if state["claim_raises"] is not None:
            raise state["claim_raises"]

    def fake_enqueue(_client: Any, job: Any) -> None:
        state["enqueues"].append(job)

    monkeypatch.setattr("sentient_api.routers.approvals.tenant_session", fake_session)
    monkeypatch.setattr("sentient_api.routers.approvals.claim_resume_intent", fake_claim)
    monkeypatch.setattr("sentient_api.routers.approvals.enqueue_resume", fake_enqueue)
    monkeypatch.setattr(
        "sentient_api.routers.approvals.redis_lib.Redis.from_url",
        MagicMock(return_value=MagicMock()),
    )
    return state


def _post_approve(client: TestClient, inv_id: str, **body: Any) -> Any:
    payload = {"approved": True, "notes": "looks good", **body}
    return client.post(f"/api/approvals/{inv_id}", json=payload)


def test_approval_404_when_missing(wk9_client: TestClient, patch_approvals: dict[str, Any]) -> None:
    patch_approvals["responses"] = [None]  # SELECT returns nothing
    r = _post_approve(wk9_client, str(uuid4()))
    assert r.status_code == 404


def test_approval_409_when_not_pending(
    wk9_client: TestClient, patch_approvals: dict[str, Any]
) -> None:
    patch_approvals["responses"] = [("approved",)]
    r = _post_approve(wk9_client, str(uuid4()))
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "not_pending_approval"


def test_approval_409_when_already_submitted(
    wk9_client: TestClient, patch_approvals: dict[str, Any]
) -> None:
    """Cluster D HIGH-13: 409 surfaces from `claim_resume_intent` raise."""
    from uuid import UUID as _UUID

    from sentient_common.resume import ResumeAlreadySubmitted

    patch_approvals["responses"] = [("pending",)]
    patch_approvals["claim_raises"] = ResumeAlreadySubmitted(
        _UUID("00000000-0000-0000-0000-000000000000")
    )
    r = _post_approve(wk9_client, str(uuid4()))
    assert r.status_code == 409
    assert r.json()["detail"] == "decision_already_submitted"


def test_approval_happy_path_claims_intent_and_enqueues(
    wk9_client: TestClient, patch_approvals: dict[str, Any]
) -> None:
    patch_approvals["responses"] = [("pending",)]
    inv_id = str(uuid4())
    r = _post_approve(wk9_client, inv_id, approved=False, notes="false positive")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["queued"] is True
    assert body["status"] == "resume_enqueued"
    # Cluster D HIGH-13: dedup + audit run inside claim_resume_intent.
    assert len(patch_approvals["claim_calls"]) == 1
    claim = patch_approvals["claim_calls"][0]
    assert claim["actor"] == "api:approvals"
    assert claim["approved"] is False
    assert claim["notes"] == "false positive"
    assert len(patch_approvals["enqueues"]) == 1
    job = patch_approvals["enqueues"][0]
    assert str(job.investigation_id) == inv_id
    assert job.approved is False
    assert job.notes == "false positive"


def test_approval_caps_long_notes(wk9_client: TestClient, patch_approvals: dict[str, Any]) -> None:
    """ResumeJob enforces a 1024-char cap; the API should 422 longer notes."""
    patch_approvals["responses"] = [("pending",)]
    r = wk9_client.post(
        f"/api/approvals/{uuid4()}",
        json={"approved": True, "notes": "x" * 2000},
    )
    assert r.status_code == 422


def test_pending_inbox(wk9_client: TestClient, patch_approvals: dict[str, Any]) -> None:
    inv_id = str(uuid4())
    inc_id = str(uuid4())
    from datetime import UTC, datetime

    response_row = (
        inv_id,
        inc_id,
        datetime.now(UTC),
        "high",
        "true_positive",
        "investigation summary",
        "approved",
    )

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            return MagicMock(all=lambda: [response_row])

        conn.execute.side_effect = execute
        yield conn

    # Override the patched session for this test only.
    from unittest.mock import patch as _patch

    import pytest as _pytest  # noqa: F401

    with _patch("sentient_api.routers.approvals.tenant_session", fake_session):
        r = wk9_client.get("/api/approvals/pending")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["investigation_id"] == inv_id
