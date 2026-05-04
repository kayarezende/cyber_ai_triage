"""Cluster D HIGH-13: shared resume dedup via `claim_resume_intent`.

Both the API submit handler (`apps/api/src/sentient_api/routers/approvals.py`)
and the CLI dev hack (`apps/orchestrator/src/sentient_orchestrator/cli_resume.py`)
must claim through the same helper. The CLI previously bypassed dedup
entirely — a second analyst could resume an investigation already
decided through the web UI without any audit row recording the conflict.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from uuid import UUID

import pytest

from sentient_common import resume as resume_mod
from sentient_common.resume import ResumeAlreadySubmitted, claim_resume_intent

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")


class _Result:
    def __init__(self, *, first: tuple[Any, ...] | None = None, rowcount: int = 1) -> None:
        self._first = first
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return self._first


class _Conn:
    """Fake conn for `claim_resume_intent`. The helper executes:

    1. SELECT id FROM investigations … FOR UPDATE  → row found / row None
    2. SELECT 1 FROM audit_log WHERE … action='human_decision_submitted'
       → returning a row triggers `ResumeAlreadySubmitted`
    """

    def __init__(
        self,
        *,
        investigation_exists: bool = True,
        prior_audit_row_exists: bool = False,
    ) -> None:
        self._inv = investigation_exists
        self._prior_audit = prior_audit_row_exists
        self.executed_sql: list[str] = []
        self.executed_params: list[dict[str, Any]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(getattr(stmt, "text", stmt))
        self.executed_sql.append(sql)
        self.executed_params.append(params or {})
        if "FROM investigations" in sql and "FOR UPDATE" in sql:
            return _Result(first=(str(INV),) if self._inv else None)
        if "FROM audit_log" in sql and "human_decision_submitted" in sql:
            return _Result(first=(1,) if self._prior_audit else None)
        if "INSERT INTO audit_log" in sql:
            return _Result(rowcount=1)
        return _Result(rowcount=1)


def _patch_session(monkeypatch: pytest.MonkeyPatch, conn: _Conn) -> None:
    @contextmanager
    def session(_tid: UUID) -> Any:
        yield conn

    monkeypatch.setattr(resume_mod, "tenant_session", session)


# ---------------------------------------------------------------- claim_resume_intent


def test_first_call_inserts_audit_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _Conn(investigation_exists=True, prior_audit_row_exists=False)
    _patch_session(monkeypatch, conn)
    claim_resume_intent(
        investigation_id=INV,
        tenant_id=TENANT,
        approved=True,
        analyst_id=None,
        notes="approve",
        actor="api:approvals",
        trace_id="trace-1",
    )
    sqls = " ".join(conn.executed_sql)
    assert "FOR UPDATE" in sqls
    assert "INSERT INTO audit_log" in sqls


def test_second_call_raises_resume_already_submitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _Conn(investigation_exists=True, prior_audit_row_exists=True)
    _patch_session(monkeypatch, conn)
    with pytest.raises(ResumeAlreadySubmitted) as exc:
        claim_resume_intent(
            investigation_id=INV,
            tenant_id=TENANT,
            approved=True,
            analyst_id=None,
            notes="approve",
            actor="api:approvals",
            trace_id="trace-2",
        )
    assert exc.value.investigation_id == INV
    # No INSERT executed when the prior row was found.
    assert not any("INSERT INTO audit_log" in s for s in conn.executed_sql)


def test_missing_investigation_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller (API) maps RuntimeError → 404."""
    conn = _Conn(investigation_exists=False, prior_audit_row_exists=False)
    _patch_session(monkeypatch, conn)
    with pytest.raises(RuntimeError, match="not found"):
        claim_resume_intent(
            investigation_id=INV,
            tenant_id=TENANT,
            approved=True,
            analyst_id=None,
            notes="",
            actor="api:approvals",
            trace_id="trace-3",
        )


# ---------------------------------------------------------------- CLI integration


def test_cli_main_returns_3_on_resume_already_submitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`cli_resume.main` must exit non-zero (3) when the dedup raises."""
    from sentient_orchestrator import cli_resume as cli_mod

    monkeypatch.setattr(cli_mod, "_load_tenant_id", lambda _iid: TENANT)

    def _raise(**_kwargs: Any) -> None:
        raise ResumeAlreadySubmitted(INV)

    monkeypatch.setattr(cli_mod, "claim_resume_intent", _raise)

    rc = cli_mod.main(
        [
            "--investigation-id",
            str(INV),
            "--approve",
        ]
    )
    assert rc == 3


def test_cli_main_invokes_resume_when_claim_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: claim succeeds → resume_investigation invoked."""
    from sentient_orchestrator import cli_resume as cli_mod

    monkeypatch.setattr(cli_mod, "_load_tenant_id", lambda _iid: TENANT)
    monkeypatch.setattr(cli_mod, "claim_resume_intent", lambda **_kw: None)

    invoked: dict[str, Any] = {}

    async def _fake_resume(job: Any) -> int:
        invoked["job"] = job
        return 0

    monkeypatch.setattr(cli_mod, "resume_investigation", _fake_resume)

    rc = cli_mod.main(
        [
            "--investigation-id",
            str(INV),
            "--approve",
        ]
    )
    assert rc == 0
    assert invoked["job"].investigation_id == INV
    assert invoked["job"].approved is True


# API HTTP integration coverage lives in
# `apps/api/tests/test_approvals_router.py::test_approval_409_when_already_submitted`
# — uses the wk9_client TestClient fixture + patches
# `sentient_api.routers.approvals.claim_resume_intent` to raise.
