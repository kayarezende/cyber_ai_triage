"""Cluster B HIGH-2: `_load_writeback_mode` distinguishes missing tenant from NULL.

Pre-fix, both states returned `'hec_only'` silently — admin had no way to
spot a misconfigured tenant_id (verdicts post to HEC against a tenant that
doesn't exist; ES `notable_update` is silently skipped). Post-fix:
  - row missing → raise `WritebackTenantMissingError`
  - row exists, value NULL → `'hec_only'` (legitimate default per ADR-0018)
  - row exists, value `'dual'` / `'hec_only'` → return as-is
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from langchain_core.tools import tool

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation.nodes import (
    WritebackTenantMissingError,
    _load_writeback_mode,
    reset_node_call_counts,
    writeback_node,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")


# ---- direct loader semantics ----


def _conn_returning(value: Any) -> Any:
    """Build a fake conn whose execute().first() returns the given row tuple,
    or None for "no row"."""
    conn = MagicMock()
    cursor = MagicMock()
    cursor.first.return_value = value
    conn.execute.return_value = cursor
    return conn


def test_loader_raises_on_missing_tenant() -> None:
    conn = _conn_returning(None)
    with pytest.raises(WritebackTenantMissingError) as exc_info:
        _load_writeback_mode(conn, TENANT)
    assert str(TENANT) in str(exc_info.value)


def test_loader_returns_hec_only_on_null_value() -> None:
    conn = _conn_returning((None,))
    assert _load_writeback_mode(conn, TENANT) == "hec_only"


def test_loader_returns_hec_only_on_empty_string_value() -> None:
    """Defensive: legacy schemas may have stored '' instead of NULL."""
    conn = _conn_returning(("",))
    assert _load_writeback_mode(conn, TENANT) == "hec_only"


def test_loader_returns_dual() -> None:
    conn = _conn_returning(("dual",))
    assert _load_writeback_mode(conn, TENANT) == "dual"


def test_loader_returns_hec_only_explicit() -> None:
    conn = _conn_returning(("hec_only",))
    assert _load_writeback_mode(conn, TENANT) == "hec_only"


# ---- writeback_node integration ----


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    yield MagicMock()


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


class _FakeFinding:
    def to_hec_dict(self) -> dict[str, Any]:
        return {"class_uid": 2004}


@tool
def siem_hec_post(event: dict[str, Any], index: str) -> dict[str, Any]:
    """Stub HEC tool — never invoked because tenant-missing short-circuits."""
    return {"success": True}


def _state() -> dict[str, Any]:
    return {
        "incident_id": str(INC),
        "draft_verdict": {
            "verdict": "true_positive",
            "confidence": 88,
            "severity": "high",
            "summary": "x",
            "mitre_techniques": ["T1059"],
        },
        "approval_status": "approved",
    }


def _config() -> dict[str, Any]:
    return {
        "configurable": {
            "tenant_id": str(TENANT),
            "investigation_id": str(INV),
            "finding": _FakeFinding(),
            "tools": [siem_hec_post],
            "mitre_descs": {},
        }
    }


@pytest.mark.asyncio
async def test_writeback_node_handles_tenant_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_calls: list[tuple[str, dict[str, Any]]] = []

    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    def _raising_loader(_conn: Any, _tid: UUID) -> str:
        raise WritebackTenantMissingError(str(TENANT))

    monkeypatch.setattr(nodes, "_load_writeback_mode", _raising_loader)
    monkeypatch.setattr(nodes, "_load_siem_notable_id", lambda _c, _i: None)

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            audit_calls.append((name, kwargs))

        return _f

    monkeypatch.setattr(
        nodes.audit,
        "emit_writeback_tenant_missing",
        _track("writeback_tenant_missing"),
    )
    monkeypatch.setattr(nodes.audit, "emit_writeback_failed", _track("writeback_failed"))
    # The node also emits writeback_attempted on the rejected-status branch
    # but never reaches it on the missing-tenant path; track defensively.
    monkeypatch.setattr(
        nodes.audit,
        "emit_writeback_attempted",
        _track("writeback_attempted"),
    )

    delta = await writeback_node(_state(), _config())  # type: ignore[arg-type]

    assert delta["writeback_status"] == "failed"
    assert delta["writeback_attempts"][0]["tool"] == "writeback_mode_loader"
    assert delta["writeback_attempts"][0]["ok"] is False

    audit_names = [name for name, _ in audit_calls]
    assert "writeback_tenant_missing" in audit_names
    assert "writeback_failed" in audit_names

    failed_kwargs = next(k for n, k in audit_calls if n == "writeback_failed")
    assert failed_kwargs["error"] == "tenant_missing"
    assert failed_kwargs["mode"] == "unknown"
