"""Cluster E HIGH-12: emit_with_fallback inserts into audit_chain_gap on failure.

Bare ``try/except: log.exception(...)`` swallowed audit emit errors silently —
``verify_chain`` then accepted the partial chain as intact. This test exercises
three scenarios:
  * happy path: emit succeeds, no fallback row written
  * emit raises: row written to ``audit_chain_gap`` with action + error message
  * emit AND audit_chain_gap insert raise: function returns without
    propagating (best-effort)
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import audit as audit_mod

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("33333333-3333-3333-3333-333333333333")


class _FakeConn:
    def __init__(self) -> None:
        self.executes: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(getattr(stmt, "text", stmt))
        self.executes.append((sql, params or {}))
        return MagicMock()


@pytest.fixture
def patched_session(
    monkeypatch: pytest.MonkeyPatch,
) -> list[_FakeConn]:
    conns: list[_FakeConn] = []

    @contextmanager
    def session(_tid: UUID) -> Any:
        conn = _FakeConn()
        conns.append(conn)
        yield conn

    monkeypatch.setattr(audit_mod, "tenant_session", session)
    return conns


def test_happy_path_no_gap_row(patched_session: list[_FakeConn]) -> None:
    calls: list[dict[str, Any]] = []

    def fake_emit(_conn: object, **kwargs: Any) -> None:
        calls.append(kwargs)

    audit_mod.emit_with_fallback(
        fake_emit,
        tenant_id=TENANT,
        investigation_id=INV,
        fallback_action="review_skipped",
        reason="ok",
    )
    assert len(calls) == 1
    assert calls[0]["reason"] == "ok"
    # No audit_chain_gap INSERT.
    for conn in patched_session:
        for sql, _ in conn.executes:
            assert "audit_chain_gap" not in sql


def test_emit_failure_writes_gap_row(patched_session: list[_FakeConn]) -> None:
    def fake_emit(_conn: object, **_kwargs: Any) -> None:
        raise RuntimeError("audit chain write blew up")

    audit_mod.emit_with_fallback(
        fake_emit,
        tenant_id=TENANT,
        investigation_id=INV,
        fallback_action="review_skipped",
        reason="ignored",
    )
    # Two sessions opened: failed emit (1st) + gap-insert (2nd).
    gap_inserts = [
        (sql, params)
        for conn in patched_session
        for sql, params in conn.executes
        if "audit_chain_gap" in sql
    ]
    assert len(gap_inserts) == 1
    sql, params = gap_inserts[0]
    assert "INSERT INTO audit_chain_gap" in sql
    assert params["tenant_id"] == str(TENANT)
    assert params["investigation_id"] == str(INV)
    assert params["attempted_action"] == "review_skipped"
    assert "RuntimeError" in params["error_message"]


def test_double_failure_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both emit AND audit_chain_gap insert raise. Function must not propagate."""

    def fake_emit(_conn: object, **_kwargs: Any) -> None:
        raise RuntimeError("primary failure")

    @contextmanager
    def broken_session(_tid: UUID) -> Any:
        raise RuntimeError("DB pool exhausted")
        yield  # unreachable, satisfies generator protocol

    monkeypatch.setattr(audit_mod, "tenant_session", broken_session)

    audit_mod.emit_with_fallback(
        fake_emit,
        tenant_id=TENANT,
        investigation_id=INV,
        fallback_action="manifest_upload_failed",
        error_type="StorageError",
        error_message="bucket gone",
    )
    # If we reach here, no exception propagated. Pass.


def test_tenant_scope_emit_with_null_investigation_id(
    patched_session: list[_FakeConn],
) -> None:
    def fake_emit(_conn: object, **_kwargs: Any) -> None:
        raise RuntimeError("boom")

    audit_mod.emit_with_fallback(
        fake_emit,
        tenant_id=TENANT,
        investigation_id=None,
        fallback_action="ingest_validation_failed",
    )
    gap_inserts = [
        (sql, params)
        for conn in patched_session
        for sql, params in conn.executes
        if "audit_chain_gap" in sql
    ]
    assert len(gap_inserts) == 1
    _, params = gap_inserts[0]
    assert params["investigation_id"] is None
    assert params["attempted_action"] == "ingest_validation_failed"
