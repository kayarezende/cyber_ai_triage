"""Wk-9 tests for the investigations router.

DB + storage are patched at the router module level — same pattern as
`test_incidents_ingest.py` — so the suite runs without Postgres / MinIO.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def patch_db(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch tenant_session inside the investigations router with a capture
    that returns scripted rows for `conn.execute(...)`.

    Tests set `responses` to a list of return values; each `execute` pops the
    next.
    """
    state: dict[str, Any] = {"responses": [], "calls": []}

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def capture_execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            state["calls"].append((str(stmt), params or {}))
            if not state["responses"]:
                return MagicMock(first=lambda: None, all=lambda: [])
            response = state["responses"].pop(0)
            if isinstance(response, list):
                return MagicMock(
                    first=lambda r=response: r[0] if r else None,
                    all=lambda r=response: r,
                    __iter__=lambda self, r=response: iter(r),
                )
            return MagicMock(first=lambda r=response: r, all=lambda: [response])

        conn.execute.side_effect = capture_execute
        yield conn

    monkeypatch.setattr(
        "sentient_api.routers.investigations.tenant_session", fake_session
    )
    return state


@pytest.fixture
def patch_storage(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"body": b"", "raise_": None}

    def fake_download(*, bucket: str, key: str) -> bytes:
        state["called"] = {"bucket": bucket, "key": key}
        if state["raise_"] is not None:
            raise state["raise_"]
        return state["body"]

    monkeypatch.setattr(
        "sentient_api.routers.investigations.download_evidence", fake_download
    )
    return state


def test_list_investigations_empty(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    patch_db["responses"] = [[]]
    r = wk9_client.get("/api/investigations")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"] == []
    assert body["next_cursor"] is None


def test_list_investigations_returns_summary(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    inv_id = uuid4()
    inc_id = uuid4()
    patch_db["responses"] = [
        [
            (
                str(inv_id), str(inc_id), datetime.now(UTC), datetime.now(UTC),
                "done", "true_positive", 0.85, "high",
                ["T1059.001"], "Brief summary of the verdict.",
                "approved", "approved", "succeeded", None, 0.05,
            ),
        ]
    ]
    r = wk9_client.get("/api/investigations")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(inv_id)
    assert items[0]["mitre_techniques"] == ["T1059.001"]
    assert items[0]["confidence"] == 0.85


def test_get_investigation_404(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    patch_db["responses"] = [None]
    r = wk9_client.get(f"/api/investigations/{uuid4()}")
    assert r.status_code == 404


def test_get_investigation_detail(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    inv_id = uuid4()
    inc_id = uuid4()
    tenant_id = uuid4()
    patch_db["responses"] = [
        # detail row
        (
            str(inv_id), str(tenant_id), str(inc_id), "done",
            "siem-notable-1", "splunk", {"foo": "bar"},
            "thread-x", datetime.now(UTC), datetime.now(UTC),
            "true_positive", 0.85, "high",
            ["T1059.001"], "summary",
            "review notes", "approved", {"reviewer": "x"},
            "approved", None, "approved by analyst",
            None, None,
            "succeeded", [{"tool": "hec"}],
            [{"rule_id": "r1"}], None,
            "manifests/x.json",
            12, 34, 0.05, {"out": "ocsf"},
            True,
        ),
        # mitre lookup row
        [("T1059.001", "PowerShell", ["TA0002"])],
    ]
    r = wk9_client.get(f"/api/investigations/{inv_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(inv_id)
    assert body["mitre_resolved"][0]["technique_id"] == "T1059.001"
    assert body["mitre_resolved"][0]["name"] == "PowerShell"
    assert body["writeback_attempts"] == [{"tool": "hec"}]
    assert body["decision_submitted"] is True


def test_get_manifest_404_when_no_key(
    wk9_client: TestClient,
    patch_db: dict[str, Any],
    patch_storage: dict[str, Any],
) -> None:
    patch_db["responses"] = [(None,)]
    r = wk9_client.get(f"/api/investigations/{uuid4()}/manifest")
    assert r.status_code == 404


def test_get_manifest_returns_json(
    wk9_client: TestClient,
    patch_db: dict[str, Any],
    patch_storage: dict[str, Any],
) -> None:
    patch_db["responses"] = [("manifests/x.json",)]
    patch_storage["body"] = b'{"hello": "world"}'
    r = wk9_client.get(f"/api/investigations/{uuid4()}/manifest")
    assert r.status_code == 200
    assert r.json() == {"hello": "world"}


def test_get_manifest_502_on_invalid_json(
    wk9_client: TestClient,
    patch_db: dict[str, Any],
    patch_storage: dict[str, Any],
) -> None:
    patch_db["responses"] = [("manifests/x.json",)]
    patch_storage["body"] = b"not-json"
    r = wk9_client.get(f"/api/investigations/{uuid4()}/manifest")
    assert r.status_code == 502


def test_timeline_404_when_investigation_missing(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    patch_db["responses"] = [None]
    r = wk9_client.get(f"/api/investigations/{uuid4()}/timeline")
    assert r.status_code == 404


def test_timeline_returns_audit_rows(
    wk9_client: TestClient, patch_db: dict[str, Any]
) -> None:
    inv_id = uuid4()
    patch_db["responses"] = [
        (1,),  # exists check
        [
            (
                42,
                "orchestrator:investigation",
                "investigation_started",
                {"thread_id": "t-1"},
                datetime.now(UTC),
            )
        ],
    ]
    r = wk9_client.get(f"/api/investigations/{inv_id}/timeline")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["action"] == "investigation_started"
