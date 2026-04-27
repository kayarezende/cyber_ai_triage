"""Investigation runner tests — verify status transitions + audit trail.

Mocks the whole DB + LLMRouter layer; asserts on the SQL strings + audit
log calls the runner emits. Real DB integration lives in
`evals/harness/test_wk5_triage_smoke.py`.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_common.jobs import IngestJob
from sentient_orchestrator import runner as runner_module
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.triage.schemas import TriageOutput

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
INCIDENT_ID = UUID("22222222-2222-2222-2222-222222222222")


def _job() -> IngestJob:
    return IngestJob(
        incident_id=INCIDENT_ID,
        tenant_id=TENANT_ID,
        enqueued_at=datetime(2026, 4, 27, tzinfo=UTC),
        trace_id="trace-1",
    )


def _ocsf_payload() -> dict[str, Any]:
    """Minimum-valid OCSF DetectionFinding payload."""
    return {
        "category_uid": 2,
        "class_uid": 2004,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": 3,
        "time": 1700000000000,
        "metadata": {
            "version": "1.3.0",
            "log_provider": "splunk",
            "product": {"name": "Splunk", "vendor_name": "Splunk Inc."},
        },
        "finding_info": {
            "uid": "fid-test",
            "title": "Test Finding",
            "analytic": {
                "name": "test analytic",
                "type_id": 2,
                "uid": "an-1",
                "version": "1",
            },
        },
        "mitre_techniques": [],
        "attacks": [],
    }


class _FakeConn:
    """Records execute() calls + serves the SELECT incidents.ocsf_normalized stub."""

    def __init__(
        self,
        *,
        ocsf_payload: dict[str, Any] | None = None,
        incident_status: str = "new",
    ) -> None:
        self._ocsf = ocsf_payload if ocsf_payload is not None else _ocsf_payload()
        self._incident_status = incident_status
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        if "SELECT ocsf_normalized FROM incidents" in sql:
            return _Result(first=(self._ocsf,))
        if "FROM mitre_techniques" in sql:
            return _Result(rows=[])
        if "UPDATE incidents SET status = 'triaging'" in sql:
            # Status guard — UPDATE matches when status='new'.
            return _Result(rowcount=1 if self._incident_status == "new" else 0)
        return _Result(first=None, rowcount=1)


class _Result:
    def __init__(
        self,
        *,
        first: tuple[Any, ...] | None = None,
        rows: list[tuple[Any, ...]] | None = None,
        rowcount: int = 0,
    ) -> None:
        self._first = first
        self._rows = rows or []
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return self._first

    def all(self) -> list[tuple[Any, ...]]:
        return self._rows


@pytest.fixture
def fake_conn() -> _FakeConn:
    return _FakeConn()


@pytest.fixture
def patch_session(
    monkeypatch: pytest.MonkeyPatch, fake_conn: _FakeConn
) -> _FakeConn:
    @contextmanager
    def session(_tid: UUID) -> Any:
        yield fake_conn

    monkeypatch.setattr(runner_module, "tenant_session", session)
    return fake_conn


@pytest.fixture
def audit_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def _capture(_conn: object, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(runner_module, "insert_audit_log", _capture)
    return calls


@pytest.fixture
def patch_router(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace LLMRouter with a MagicMock so __init__ doesn't hit the DB."""
    instance = MagicMock()
    monkeypatch.setattr(
        runner_module, "LLMRouter", MagicMock(return_value=instance)
    )
    return instance


@pytest.fixture
def patch_mitre(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner_module, "fetch_technique_descriptions", lambda _conn, _ids: {}
    )


def _patch_run_triage(
    monkeypatch: pytest.MonkeyPatch,
    *,
    output: TriageOutput | None = None,
    raises: BaseException | None = None,
) -> None:
    async def fake(**_kwargs: Any) -> TriageOutput:
        if raises is not None:
            raise raises
        assert output is not None
        return output

    monkeypatch.setattr(runner_module, "run_triage", fake)


def _find_action(audits: list[dict[str, Any]], action: str) -> dict[str, Any] | None:
    for entry in audits:
        if entry.get("action") == action:
            return entry
    return None


# ---------------------------------------------------------------- auto-close


@pytest.mark.asyncio
async def test_auto_closes_on_low_severity(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    _patch_run_triage(
        monkeypatch,
        output=TriageOutput(
            severity="low",
            confidence=85,
            mitre_guesses=["T1110"],
            entities_to_investigate=["host-1"],
            reasoning="benign brute-force burst from known geo.",
        ),
    )
    investigation_id = await runner_module.run_investigation(_job())

    assert isinstance(investigation_id, UUID)
    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'triaging'" in sql_blob
    assert "SET status = 'done'" in sql_blob
    assert "INSERT INTO investigations" in sql_blob

    actions = [a["action"] for a in audit_calls]
    assert "triage_started" in actions
    assert "triage_auto_close" in actions
    auto_close = _find_action(audit_calls, "triage_auto_close")
    assert auto_close is not None
    assert auto_close["details"]["severity"] == "low"
    assert auto_close["details"]["confidence"] == 85


@pytest.mark.asyncio
async def test_auto_closes_on_info_severity(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    _patch_run_triage(
        monkeypatch,
        output=TriageOutput(
            severity="info",
            confidence=92,
            mitre_guesses=[],
            entities_to_investigate=[],
            reasoning="routine internal scan.",
        ),
    )
    await runner_module.run_investigation(_job())
    assert _find_action(audit_calls, "triage_auto_close") is not None


# ---------------------------------------------------------------- escalate


@pytest.mark.asyncio
async def test_escalates_on_high_severity(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    _patch_run_triage(
        monkeypatch,
        output=TriageOutput(
            severity="high",
            confidence=80,
            mitre_guesses=["T1059.001"],
            entities_to_investigate=["wks-carol-12"],
            reasoning="encoded powershell beacon to known c2.",
        ),
    )
    await runner_module.run_investigation(_job())

    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'triaging'" in sql_blob
    # Must NOT auto-close — wk-6 LangGraph claims triaging rows.
    assert "SET status = 'done'" not in sql_blob
    # Investigation row updated with verdict='inconclusive' + reason.
    update_calls = [
        params for sql, params in patch_session.queries
        if "UPDATE investigations" in sql and "verdict" in sql
    ]
    assert any(p.get("verdict") == "inconclusive" for p in update_calls)
    assert any(
        p.get("reason") == "tier_2_pending_wk6" for p in update_calls
    )

    actions = [a["action"] for a in audit_calls]
    assert "triage_escalated" in actions


@pytest.mark.parametrize("severity", ["medium", "high", "critical"])
@pytest.mark.asyncio
async def test_escalates_for_each_high_severity(
    severity: str,
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    _patch_run_triage(
        monkeypatch,
        output=TriageOutput(
            severity=severity,  # type: ignore[arg-type]
            confidence=70,
            mitre_guesses=[],
            entities_to_investigate=[],
            reasoning=f"{severity}-severity finding.",
        ),
    )
    await runner_module.run_investigation(_job())
    assert _find_action(audit_calls, "triage_escalated") is not None
    assert _find_action(audit_calls, "triage_auto_close") is None


# ---------------------------------------------------------------- fallback exhausted


@pytest.mark.asyncio
async def test_fallback_exhausted_marks_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    _patch_run_triage(
        monkeypatch,
        raises=FallbackChainExhausted(
            role="triage", attempts=["model-a", "model-b"]
        ),
    )

    investigation_id = await runner_module.run_investigation(_job())

    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'inconclusive'" in sql_blob

    audit = _find_action(audit_calls, "triage_failed_fallback_exhausted")
    assert audit is not None
    assert audit["details"]["attempts"] == ["model-a", "model-b"]
    assert isinstance(investigation_id, UUID)


# ---------------------------------------------------------------- helpers


def test_pg_text_array() -> None:
    from sentient_orchestrator.runner import _pg_text_array

    assert _pg_text_array([]) == "{}"
    assert _pg_text_array(["T1059"]) == "{T1059}"
    assert _pg_text_array(["T1059", "T1071.004"]) == "{T1059,T1071.004}"


@pytest.mark.asyncio
async def test_missing_incident_raises(
    monkeypatch: pytest.MonkeyPatch,
    patch_router: MagicMock,
) -> None:
    @contextmanager
    def empty_session(_tid: UUID) -> Any:
        class C:
            def execute(self, _stmt: Any, _p: Any = None) -> _Result:
                return _Result(first=None)

        yield C()

    monkeypatch.setattr(runner_module, "tenant_session", empty_session)
    with pytest.raises(RuntimeError, match="not found"):
        await runner_module.run_investigation(_job())


# ---------------------------------------------------------------- unexpected error


@pytest.mark.asyncio
async def test_unexpected_error_finalized_as_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    """Auth failure / network error during triage must still leave an audit row."""
    _patch_run_triage(monkeypatch, raises=RuntimeError("upstream unreachable"))
    investigation_id = await runner_module.run_investigation(_job())

    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'inconclusive'" in sql_blob
    audit = _find_action(audit_calls, "triage_failed_fallback_exhausted")
    assert audit is not None
    assert audit["details"]["error_type"] == "RuntimeError"
    assert "upstream unreachable" in audit["details"]["error"]
    assert isinstance(investigation_id, UUID)


# ---------------------------------------------------------------- status guard


@pytest.mark.asyncio
async def test_redelivered_job_skipped(
    monkeypatch: pytest.MonkeyPatch,
    audit_calls: list[dict[str, Any]],
    patch_router: MagicMock,
    patch_mitre: None,
) -> None:
    """A re-delivered job against an already-triaging incident is a no-op."""
    fake = _FakeConn(incident_status="triaging")  # already claimed

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield fake

    monkeypatch.setattr(runner_module, "tenant_session", session)
    _patch_run_triage(
        monkeypatch,
        output=TriageOutput(
            severity="low",
            confidence=80,
            mitre_guesses=[],
            entities_to_investigate=[],
            reasoning="should not run.",
        ),
    )

    investigation_id = await runner_module.run_investigation(_job())

    # Investigation row NOT inserted; triage_started NOT logged.
    sql_blob = " ".join(q[0] for q in fake.queries)
    assert "INSERT INTO investigations" not in sql_blob
    assert _find_action(audit_calls, "triage_started") is None
    assert _find_action(audit_calls, "triage_auto_close") is None
    assert isinstance(investigation_id, UUID)
