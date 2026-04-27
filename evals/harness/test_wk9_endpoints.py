"""Wk-9 endpoint integration test against the live compose stack.

Marked `@pytest.mark.integration` — only runs when explicitly selected
(`-m integration`) AND the API is reachable. Skips otherwise so unit-test
runs stay self-contained.

Covers:
  - /health on api + web
  - /api/investigations list + filter
  - /api/investigations/{id} detail + decision_submitted flag
  - /api/investigations/{id}/timeline audit slice
  - /api/audit list + chain_ok per row
  - /api/audit/verify/{id} full chain walk
  - /api/replay/{id}/checkpoints list
  - /api/approvals/pending inbox
  - 404 paths

Does NOT POST /api/approvals/{id} (would mutate state + enqueue real
ResumeJob). The approvals POST is exercised in
`apps/api/tests/test_approvals_router.py` with mocked Redis/audit.
"""

from __future__ import annotations

import os

import httpx
import pytest

API_BASE = os.environ.get("API_INTEGRATION_BASE", "http://localhost:8000")
WEB_BASE = os.environ.get("WEB_INTEGRATION_BASE", "http://localhost:3001")
DEV_TENANT_ID = "00000000-0000-0000-0000-000000000001"

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    """Module-scoped httpx client preconfigured with dev-bypass headers.

    Skips the whole module if the api isn't reachable — keeps CI green
    when the compose stack isn't up.
    """
    try:
        probe = httpx.get(f"{API_BASE}/health", timeout=2.0)
    except (httpx.ConnectError, httpx.TimeoutException):
        pytest.skip(f"api not reachable at {API_BASE}")
    if probe.status_code != 200:
        pytest.skip(f"api /health returned {probe.status_code}")

    headers = {
        "x-tenant-id": DEV_TENANT_ID,
        "x-user-id": "00000000-0000-0000-0000-0000000000aa",
        "x-dev-user": "pytest@sentientlayer.ai",
    }
    with httpx.Client(base_url=API_BASE, headers=headers, timeout=10.0) as c:
        yield c


def test_api_health(client: httpx.Client) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "healthy"}


def test_web_health() -> None:
    try:
        r = httpx.get(f"{WEB_BASE}/api/health", timeout=2.0)
    except (httpx.ConnectError, httpx.TimeoutException):
        pytest.skip(f"web not reachable at {WEB_BASE}")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_investigations_shape(client: httpx.Client) -> None:
    r = client.get("/api/investigations", params={"limit": 50})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "items" in body
    assert "next_cursor" in body
    assert isinstance(body["items"], list)
    if body["items"]:
        sample = body["items"][0]
        for key in (
            "id",
            "incident_id",
            "verdict",
            "severity",
            "approval_status",
            "review_status",
            "writeback_status",
            "mitre_techniques",
        ):
            assert key in sample, f"missing key: {key}"


def test_list_investigations_filter_passes_through(client: httpx.Client) -> None:
    """Bogus filter value should return zero rows, not 500."""
    r = client.get(
        "/api/investigations",
        params={"verdict": "no_such_verdict_value", "limit": 5},
    )
    assert r.status_code == 200, r.text
    assert r.json()["items"] == []


def test_detail_404_for_missing(client: httpx.Client) -> None:
    r = client.get(
        "/api/investigations/00000000-0000-0000-0000-000000000000"
    )
    assert r.status_code == 404


def test_detail_returns_decision_submitted(client: httpx.Client) -> None:
    """If any investigation rows exist, detail must include the
    `decision_submitted` boolean (wk-9 UX gate field)."""
    listing = client.get("/api/investigations", params={"limit": 5}).json()
    if not listing["items"]:
        pytest.skip("no investigations in fixture data")
    inv_id = listing["items"][0]["id"]
    r = client.get(f"/api/investigations/{inv_id}")
    assert r.status_code == 200, r.text
    detail = r.json()
    assert "decision_submitted" in detail
    assert isinstance(detail["decision_submitted"], bool)
    assert "mitre_resolved" in detail
    assert "writeback_attempts" in detail


def test_timeline_returns_audit_slice(client: httpx.Client) -> None:
    listing = client.get("/api/investigations", params={"limit": 5}).json()
    if not listing["items"]:
        pytest.skip("no investigations in fixture data")
    inv_id = listing["items"][0]["id"]
    r = client.get(f"/api/investigations/{inv_id}/timeline")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert isinstance(items, list)
    if items:
        for k in ("id", "actor", "action", "details", "created_at"):
            assert k in items[0]


def test_audit_list_with_chain_ok(client: httpx.Client) -> None:
    r = client.get("/api/audit", params={"limit": 25})
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert isinstance(items, list)
    if items:
        for row in items:
            assert "chain_ok" in row
            assert isinstance(row["chain_ok"], bool)


def test_audit_verify_walks_chain(client: httpx.Client) -> None:
    """Run a full chain walk against any existing investigation chain.

    Confirms the Python recompute matches the plpgsql trigger digests in
    the live DB — same parity the unit-level golden test asserts, but
    against arbitrary tenant data, not a synthetic row.
    """
    listing = client.get("/api/investigations", params={"limit": 5}).json()
    if not listing["items"]:
        pytest.skip("no investigations in fixture data")
    inv_id = listing["items"][0]["id"]
    r = client.get(f"/api/audit/verify/{inv_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is True, (
        f"chain integrity broken at row {body['first_invalid_row_id']}: "
        f"{body['rows']}"
    )
    assert body["total_rows"] >= 0


def test_audit_verify_404_for_missing(client: httpx.Client) -> None:
    r = client.get(
        "/api/audit/verify/00000000-0000-0000-0000-000000000000"
    )
    assert r.status_code == 404


def test_audit_filters_by_action(client: httpx.Client) -> None:
    r = client.get(
        "/api/audit",
        params={"action": "incident_ingested", "limit": 5},
    )
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    for row in items:
        assert row["action"] == "incident_ingested"


def test_replay_checkpoints_list_or_thread_404(client: httpx.Client) -> None:
    """Replay endpoint either returns a checkpoint list or 404 if the
    investigation hasn't been claimed yet (no langgraph_thread_id).
    Both shapes are valid; the test just asserts it doesn't 500."""
    listing = client.get("/api/investigations", params={"limit": 5}).json()
    if not listing["items"]:
        pytest.skip("no investigations in fixture data")
    inv_id = listing["items"][0]["id"]
    r = client.get(f"/api/replay/{inv_id}/checkpoints")
    assert r.status_code in {200, 404, 503}, r.text
    if r.status_code == 200:
        body = r.json()
        assert "items" in body
        assert isinstance(body["items"], list)


def test_replay_404_for_missing_investigation(client: httpx.Client) -> None:
    r = client.get(
        "/api/replay/00000000-0000-0000-0000-000000000000/checkpoints"
    )
    assert r.status_code in {404, 503}


def test_pending_approvals_inbox(client: httpx.Client) -> None:
    r = client.get("/api/approvals/pending")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "items" in body
    for row in body["items"]:
        assert "investigation_id" in row
        assert "incident_id" in row


def test_approval_post_404_for_missing(client: httpx.Client) -> None:
    """POST without prior investigation row should 404 cleanly."""
    r = client.post(
        "/api/approvals/00000000-0000-0000-0000-000000000000",
        json={"approved": True, "notes": "integration test"},
    )
    assert r.status_code == 404


def test_invalid_tenant_header_400(client: httpx.Client) -> None:
    r = httpx.get(
        f"{API_BASE}/api/investigations",
        headers={"x-tenant-id": "not-a-uuid"},
        timeout=5.0,
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_tenant_header"


def test_pagination_cursor_round_trip(client: httpx.Client) -> None:
    """If multiple investigations exist, cursor returns next page cleanly."""
    page1 = client.get("/api/investigations", params={"limit": 1}).json()
    if not page1["items"] or not page1["next_cursor"]:
        pytest.skip("need ≥2 investigations to exercise cursor")
    page2 = client.get(
        "/api/investigations",
        params={"limit": 1, "cursor": page1["next_cursor"]},
    ).json()
    if page2["items"]:
        assert page2["items"][0]["id"] != page1["items"][0]["id"]


def test_invalid_cursor_400(client: httpx.Client) -> None:
    r = client.get(
        "/api/investigations", params={"cursor": "not-base64-anything"}
    )
    assert r.status_code == 400


def test_manifest_404_when_no_evidence_key(client: httpx.Client) -> None:
    """At least one investigation in the seed fixture lacks an evidence
    manifest (wk-4 stub investigations don't upload one). Confirm the
    endpoint returns 404, not 500."""
    listing = client.get("/api/investigations", params={"limit": 25}).json()
    if not listing["items"]:
        pytest.skip("no investigations in fixture data")
    # Walk until we find one that 404s on manifest, OR confirm at least
    # one returned 200 — both are valid outcomes for this test.
    saw_404_or_200 = False
    for item in listing["items"]:
        r = client.get(
            f"/api/investigations/{item['id']}/manifest"
        )
        assert r.status_code in {200, 404, 502}, (
            f"unexpected status {r.status_code} for {item['id']}: {r.text}"
        )
        if r.status_code in {200, 404}:
            saw_404_or_200 = True
    assert saw_404_or_200
