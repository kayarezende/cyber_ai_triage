"""Tests for the worker BLPOP → run_investigation / resume dispatch paths."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from sentient_common.jobs import IngestJob, ResumeJob


def _ingest_job() -> IngestJob:
    return IngestJob(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        enqueued_at=datetime.now(UTC),
        trace_id="trace-abc",
    )


def _resume_job(*, approved: bool = True) -> ResumeJob:
    return ResumeJob(
        investigation_id=uuid4(),
        tenant_id=uuid4(),
        approved=approved,
        analyst_id=None,
        notes="ok",
        enqueued_at=datetime.now(UTC),
        trace_id="trace-resume",
    )


def test_ingest_job_round_trip() -> None:
    job = _ingest_job()
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


def test_resume_job_round_trip() -> None:
    job = _resume_job()
    restored = ResumeJob.model_validate_json(job.model_dump_json())
    assert restored == job


def test_resume_job_caps_notes_length() -> None:
    with pytest.raises(ValidationError):
        ResumeJob(
            investigation_id=uuid4(),
            tenant_id=uuid4(),
            approved=True,
            analyst_id=None,
            notes="x" * 1100,
            enqueued_at=datetime.now(UTC),
            trace_id="t",
        )


def test_process_ingest_drops_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-JSON payload logs an error and returns without invoking the runner."""
    called = False

    async def must_not_be_called(_job: IngestJob) -> UUID:
        nonlocal called
        called = True
        return uuid4()

    monkeypatch.setattr("sentient_worker.main.run_investigation", must_not_be_called)

    from sentient_worker.main import _process_ingest

    _process_ingest(b"this is not json")
    assert called is False


def test_process_ingest_swallows_runner_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the runner raises, the worker logs and continues — does not crash the loop."""

    async def boom(_job: IngestJob) -> UUID:
        raise RuntimeError("DB down")

    monkeypatch.setattr("sentient_worker.main.run_investigation", boom)

    from sentient_worker.main import _process_ingest

    payload = _ingest_job().model_dump_json().encode()
    _process_ingest(payload)  # should not raise


def test_process_ingest_invokes_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Happy path — payload parses, runner is awaited, returned id is logged."""
    seen: dict[str, Any] = {}

    async def fake_runner(job: IngestJob) -> UUID:
        seen["job"] = job
        return UUID("33333333-3333-3333-3333-333333333333")

    monkeypatch.setattr("sentient_worker.main.run_investigation", fake_runner)

    from sentient_worker.main import _process_ingest

    job = _ingest_job()
    payload = job.model_dump_json().encode()
    _process_ingest(payload)
    assert seen["job"].incident_id == job.incident_id
    assert seen["job"].tenant_id == job.tenant_id


def test_process_resume_invokes_resume_investigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path — payload parses, resume_investigation is awaited."""
    seen: dict[str, Any] = {}

    async def fake_resume(job: ResumeJob) -> int:
        seen["job"] = job
        return 0

    monkeypatch.setattr("sentient_worker.main.resume_investigation", fake_resume)

    from sentient_worker.main import _process_resume

    job = _resume_job(approved=True)
    payload = job.model_dump_json().encode()
    _process_resume(payload)
    assert seen["job"].investigation_id == job.investigation_id
    assert seen["job"].approved is True


def test_process_resume_drops_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def must_not_be_called(_job: ResumeJob) -> int:
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr("sentient_worker.main.resume_investigation", must_not_be_called)

    from sentient_worker.main import _process_resume

    _process_resume(b"not json")
    assert called is False


def test_process_resume_swallows_runner_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(_job: ResumeJob) -> int:
        raise RuntimeError("graph blew up")

    monkeypatch.setattr("sentient_worker.main.resume_investigation", boom)

    from sentient_worker.main import _process_resume

    payload = _resume_job().model_dump_json().encode()
    _process_resume(payload)  # should not raise
