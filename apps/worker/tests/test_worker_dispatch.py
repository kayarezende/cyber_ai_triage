"""Tests for the worker BLPOP → run_investigation dispatch path."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

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


def test_process_payload_drops_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-JSON payload logs an error and returns without invoking the runner."""
    called = False

    async def must_not_be_called(_job: IngestJob) -> UUID:
        nonlocal called
        called = True
        return uuid4()

    monkeypatch.setattr("sentient_worker.main.run_investigation", must_not_be_called)

    from sentient_worker.main import _process_payload

    _process_payload(b"this is not json")
    assert called is False


def test_process_payload_swallows_runner_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the runner raises, the worker logs and continues — does not crash the loop."""

    async def boom(_job: IngestJob) -> UUID:
        raise RuntimeError("DB down")

    monkeypatch.setattr("sentient_worker.main.run_investigation", boom)

    from sentient_worker.main import _process_payload

    payload = _job().model_dump_json().encode()
    _process_payload(payload)  # should not raise


def test_process_payload_invokes_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Happy path — payload parses, runner is awaited, returned id is logged."""
    seen: dict[str, Any] = {}

    async def fake_runner(job: IngestJob) -> UUID:
        seen["job"] = job
        return UUID("33333333-3333-3333-3333-333333333333")

    monkeypatch.setattr("sentient_worker.main.run_investigation", fake_runner)

    from sentient_worker.main import _process_payload

    job = _job()
    payload = job.model_dump_json().encode()
    _process_payload(payload)
    assert seen["job"].incident_id == job.incident_id
    assert seen["job"].tenant_id == job.tenant_id
