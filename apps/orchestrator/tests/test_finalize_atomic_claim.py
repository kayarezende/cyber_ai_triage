"""Cluster D CRIT-6: atomic finalize-claim guards every post-graph side effect.

Two `_finalize_after_graph` calls (or `_finalize_inconclusive` calls) on the
same investigation must produce: ONE verdict UPDATE, ONE completion audit row,
ONE manifest upload attempt. The second call short-circuits at the
`UPDATE … WHERE completed_at IS NULL RETURNING id` claim.

Mocks tenant_session so the claim returns a row on the first call and None
on subsequent calls.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import runner as runner_mod
from sentient_orchestrator.investigation.runner import (
    _claim_finalize,
    _finalize_after_graph,
    _finalize_inconclusive,
)
from sentient_orchestrator.investigation.state import InvestigationOutput

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")


class _Result:
    def __init__(
        self,
        *,
        first: tuple[Any, ...] | None = None,
        rowcount: int = 1,
    ) -> None:
        self._first = first
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return self._first


class _ClaimingConn:
    """Returns a row on the first `completed_at IS NULL` UPDATE; None after."""

    def __init__(self, *, claims_remaining: int = 1) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self._claims_remaining = claims_remaining

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        if "completed_at IS NULL" in sql and "RETURNING id" in sql:
            if self._claims_remaining > 0:
                self._claims_remaining -= 1
                return _Result(first=(str(INV),), rowcount=1)
            return _Result(first=None, rowcount=0)
        return _Result(rowcount=1)


@pytest.fixture
def conn() -> _ClaimingConn:
    return _ClaimingConn(claims_remaining=1)


@pytest.fixture(autouse=True)
def patch_session(monkeypatch: pytest.MonkeyPatch, conn: _ClaimingConn) -> _ClaimingConn:
    @contextmanager
    def session(_tid: UUID) -> Any:
        yield conn

    monkeypatch.setattr(runner_mod, "tenant_session", session)
    return conn


@pytest.fixture
def emitted(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _track(name: str) -> Any:
        def _f(_conn: object, **_kwargs: Any) -> None:
            calls.append(name)

        return _f

    monkeypatch.setattr(runner_mod, "emit_investigation_complete", _track("complete"))
    monkeypatch.setattr(runner_mod, "emit_investigation_failed", _track("failed"))
    return calls


@pytest.fixture
def manifest_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def _capture(**kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(runner_mod, "_try_upload_manifest", _capture)
    return calls


def _verdict() -> InvestigationOutput:
    return InvestigationOutput(
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1059.001"],
        summary="encoded ps c2",
        evidence=["spl: index=main"],
        reasoning="confirmed payload",
    )


# ---------------------------------------------------------------- _claim_finalize


def test_claim_finalize_writes_update_with_null_guard(conn: _ClaimingConn) -> None:
    assert _claim_finalize(INV, TENANT) is True
    sql = " ".join(q[0] for q in conn.queries)
    assert "UPDATE investigations SET completed_at = NOW()" in sql
    assert "completed_at IS NULL" in sql
    assert "RETURNING id" in sql


def test_claim_finalize_returns_false_when_already_claimed(
    conn: _ClaimingConn,
) -> None:
    assert _claim_finalize(INV, TENANT) is True
    assert _claim_finalize(INV, TENANT) is False


# ---------------------------------------------------------------- _finalize_after_graph


@pytest.mark.asyncio
async def test_finalize_after_graph_short_circuits_on_second_call(
    conn: _ClaimingConn,
    emitted: list[str],
    manifest_calls: list[dict[str, Any]],
) -> None:
    """First call writes verdict + manifest + 'complete' audit; second is a no-op."""
    final_state: Any = {
        "draft_verdict": _verdict().model_dump(),
        "approval_status": "approved",
        "writeback_status": "succeeded",
    }

    await _finalize_after_graph(
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        finding=None,  # type: ignore[arg-type]  # _finalize_after_graph reads only from final_state
        final_state=final_state,
    )
    assert emitted == ["complete"]
    assert len(manifest_calls) == 1

    # Second call: claim returns None → short-circuit before any further work.
    await _finalize_after_graph(
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        finding=None,  # type: ignore[arg-type]
        final_state=final_state,
    )
    assert emitted == ["complete"], "second call must not emit a second audit row"
    assert len(manifest_calls) == 1, "second call must not re-upload manifest"


# ---------------------------------------------------------------- _finalize_inconclusive


@pytest.mark.asyncio
async def test_finalize_inconclusive_short_circuits_on_second_call(
    conn: _ClaimingConn,
    emitted: list[str],
) -> None:
    await _finalize_inconclusive(
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        error_type="X",
        error_message="boom",
        reason="reason_x",
    )
    assert emitted == ["failed"]

    await _finalize_inconclusive(
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        error_type="Y",
        error_message="late",
        reason="reason_y",
    )
    assert emitted == ["failed"], "second inconclusive must not emit a second audit row"


def test_verdict_update_no_longer_writes_completed_at(
    conn: _ClaimingConn,
) -> None:
    """Cluster D CRIT-6 invariant: `completed_at` is owned by the claim."""
    runner_mod._update_investigation_with_verdict(
        conn,  # type: ignore[arg-type]
        investigation_id=INV,
        verdict=_verdict(),
    )
    update_sql = next(sql for sql, _ in conn.queries if "ocsf_output" in sql)
    assert "completed_at" not in update_sql
