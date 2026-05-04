"""Wk-9 tests for the audit router."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentient_common.audit import compute_audit_row_hash


@pytest.fixture
def patch_audit_session(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"responses": []}

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def execute(_stmt: Any, _params: dict[str, Any] | None = None) -> Any:
            response = state["responses"].pop(0) if state["responses"] else None
            if isinstance(response, list):
                return MagicMock(
                    first=lambda r=response: r[0] if r else None,
                    all=lambda r=response: r,
                    __iter__=lambda self, r=response: iter(r),
                )
            return MagicMock(
                first=lambda r=response: r,
                all=lambda r=response: [r] if r else [],
            )

        conn.execute.side_effect = execute
        yield conn

    monkeypatch.setattr("sentient_api.routers.audit.tenant_session", fake_session)
    return state


def _build_chain_rows(scope: str, count: int) -> list[Any]:
    """Build (id, investigation_id, actor, action, details, content_hash,
    previous_hash, hash_scope, created_at, tenant_id_text,
    investigation_id_text, details_text, created_at_text) tuples whose
    hashes form a valid chain.
    """
    tenant_id_text = "00000000-0000-0000-0000-000000000001"
    inv_id_text = "00000000-0000-0000-0000-000000000010"
    rows: list[Any] = []
    prev = ""
    for i in range(count):
        actor = "actor"
        action = f"step-{i}"
        details_text = '{"i": ' + str(i) + "}"
        created_at_text = f"2026-04-27 12:00:0{i}+00"
        digest = compute_audit_row_hash(
            hash_scope=scope,
            tenant_id_text=tenant_id_text,
            investigation_id_text=inv_id_text,
            actor=actor,
            action=action,
            details_text=details_text,
            created_at_text=created_at_text,
            previous_hash=prev,
        )
        rows.append(
            (
                100 + i,
                inv_id_text,
                actor,
                action,
                {"i": i},
                digest,
                prev,
                scope,
                datetime.now(UTC),
                tenant_id_text,
                inv_id_text,
                details_text,
                created_at_text,
            )
        )
        prev = digest
    return rows


def test_list_audit_returns_chain_ok(
    wk9_client: TestClient, patch_audit_session: dict[str, Any]
) -> None:
    rows = _build_chain_rows("investigation:abc", 3)
    patch_audit_session["responses"] = [rows]
    r = wk9_client.get("/api/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) == 3
    assert all(item["chain_ok"] is True for item in body["items"])


def test_list_audit_flags_broken_row(
    wk9_client: TestClient, patch_audit_session: dict[str, Any]
) -> None:
    rows = list(_build_chain_rows("investigation:xyz", 3))
    # Tamper with row 2's stored hash
    bad = list(rows[1])
    bad[5] = "bad-hash"
    rows[1] = tuple(bad)
    patch_audit_session["responses"] = [rows]
    r = wk9_client.get("/api/audit")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert items[0]["chain_ok"] is True
    assert items[1]["chain_ok"] is False
    assert items[2]["chain_ok"] is False  # propagated through previous_hash mismatch


def test_verify_endpoint_404(wk9_client: TestClient, patch_audit_session: dict[str, Any]) -> None:
    patch_audit_session["responses"] = [None]
    r = wk9_client.get(f"/api/audit/verify/{uuid4()}")
    assert r.status_code == 404


def test_verify_endpoint_walks_chain(
    wk9_client: TestClient, patch_audit_session: dict[str, Any]
) -> None:
    inv_id = uuid4()
    scope = f"investigation:{inv_id}"
    rows = _build_chain_rows(scope, 4)
    # Format expected by verify SQL: id, content_hash, previous_hash, hash_scope,
    # tenant_id_text, investigation_id_text, actor, action, details_text, created_at_text
    verify_rows = [(r[0], r[5], r[6], r[7], r[9], r[10], r[2], r[3], r[11], r[12]) for r in rows]
    patch_audit_session["responses"] = [(1,), verify_rows]
    r = wk9_client.get(f"/api/audit/verify/{inv_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is True
    assert body["total_rows"] == 4
