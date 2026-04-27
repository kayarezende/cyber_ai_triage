"""Tests for the worker BLPOP → stub-investigation dispatch path."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentient_common.jobs import IngestJob


def _job() -> IngestJob:
    return IngestJob(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        enqueued_at=datetime.now(UTC),
        trace_id="trace-abc",
    )


def test_ingest_job_round_trip() -> None:
    job = _job()
    payload = job.model_dump_json()
    restored = IngestJob.model_validate_json(payload)
    assert restored == job


def test_ingest_job_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        IngestJob.model_validate_json(
            '{"incident_id": "00000000-0000-0000-0000-000000000001",'
            '"tenant_id": "00000000-0000-0000-0000-000000000002",'
            '"enqueued_at": "2026-04-27T00:00:00Z",'
            '"trace_id": "x",'
            '"unexpected": "no"}'
        )


def test_run_stub_investigation_writes_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stub runs an INSERT, an UPDATE, and an audit_log INSERT inside a tenant_session."""
    from contextlib import contextmanager

    executes: list[tuple[str, dict[str, Any]]] = []
    audits: list[dict[str, Any]] = []
    sessions_opened: list[Any] = []

    @contextmanager
    def fake_session(tenant_id: Any) -> Any:
        sessions_opened.append(tenant_id)
        conn = MagicMock(name=f"conn[{tenant_id}]")

        def capture(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            executes.append((str(stmt), params or {}))
            return MagicMock()

        conn.execute.side_effect = capture
        yield conn

    def fake_audit(
        conn: Any, *, tenant_id: Any, investigation_id: Any, actor: str,
        action: str, details: dict[str, Any]
    ) -> None:
        audits.append(
            {
                "tenant_id": str(tenant_id),
                "investigation_id": str(investigation_id) if investigation_id else None,
                "actor": actor,
                "action": action,
                "details": details,
            }
        )

    monkeypatch.setattr(
        "sentient_orchestrator.stub_investigation.tenant_session", fake_session
    )
    monkeypatch.setattr(
        "sentient_orchestrator.stub_investigation.insert_audit_log", fake_audit
    )

    from sentient_orchestrator.stub_investigation import run_stub_investigation

    job = _job()
    investigation_id = run_stub_investigation(job)

    assert sessions_opened == [job.tenant_id]
    # Two SQL statements: investigations INSERT, incidents UPDATE.
    assert len(executes) == 2
    insert_sql, insert_params = executes[0]
    update_sql, update_params = executes[1]
    assert "INSERT INTO investigations" in insert_sql
    assert insert_params["incident_id"] == str(job.incident_id)
    assert insert_params["tenant_id"] == str(job.tenant_id)
    assert insert_params["id"] == str(investigation_id)
    assert "UPDATE incidents" in update_sql
    assert update_params["id"] == str(job.incident_id)

    # One audit_log entry for the stub completion.
    assert len(audits) == 1
    audit = audits[0]
    assert audit["actor"] == "worker"
    assert audit["action"] == "stub_investigation_completed"
    assert audit["investigation_id"] == str(investigation_id)
    assert audit["details"]["verdict"] == "inconclusive"
    assert audit["details"]["incident_id"] == str(job.incident_id)
    assert audit["details"]["trace_id"] == job.trace_id


def test_process_payload_drops_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A non-JSON payload logs an error and returns without invoking the stub."""
    called = False

    def must_not_be_called(_job: IngestJob) -> Any:
        nonlocal called
        called = True
        return uuid4()

    monkeypatch.setattr(
        "sentient_worker.main.run_stub_investigation", must_not_be_called
    )

    from sentient_worker.main import _process_payload

    _process_payload(b"this is not json")
    assert called is False


def test_process_payload_swallows_stub_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the stub raises, the worker logs and continues — does not crash the loop."""

    def boom(_job: IngestJob) -> Any:
        raise RuntimeError("DB down")

    monkeypatch.setattr("sentient_worker.main.run_stub_investigation", boom)

    from sentient_worker.main import _process_payload

    payload = _job().model_dump_json().encode()
    _process_payload(payload)  # should not raise
