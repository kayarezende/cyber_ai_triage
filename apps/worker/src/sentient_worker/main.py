"""Worker entrypoint.

Wk 1: BLPOP loop + sentinel heartbeat + structured logging.
Wk 4: parse the popped payload as `IngestJob` and run the wk-4 stub
investigation in-process. Wk-6 swaps the body of `run_stub_investigation`
for the real LangGraph runner; this loop stays.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path
from types import FrameType
from typing import cast

import redis
from pydantic import ValidationError

from sentient_common.jobs import QUEUE_INVESTIGATIONS, IngestJob
from sentient_common.logging import configure_logging, get_logger
from sentient_orchestrator.stub_investigation import run_stub_investigation

_SENTINEL = Path("/tmp/ready")
_BLPOP_TIMEOUT_SECONDS = 30

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    _shutdown = True
    log.info("worker shutting down", signal=signum)


def _process_payload(payload: bytes) -> None:
    try:
        job = IngestJob.model_validate_json(payload)
    except ValidationError as exc:
        log.error(
            "dropping malformed job",
            payload_bytes=len(payload),
            errors=exc.errors(),
        )
        return

    job_log = log.bind(
        trace_id=job.trace_id,
        incident_id=str(job.incident_id),
        tenant_id=str(job.tenant_id),
    )
    try:
        investigation_id = run_stub_investigation(job)
    except Exception:
        # Wk-4: at-most-once. Wk-6 adds a reliable queue + DLQ.
        job_log.exception("stub investigation failed")
        return
    job_log.info("stub investigation done", investigation_id=str(investigation_id))


def main() -> int:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = redis.Redis.from_url(url)
    log.info("worker ready", queue=QUEUE_INVESTIGATIONS)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not _shutdown:
        _SENTINEL.touch()
        result = cast(
            "tuple[bytes, bytes] | None",
            client.blpop([QUEUE_INVESTIGATIONS], timeout=_BLPOP_TIMEOUT_SECONDS),
        )
        if result is None:
            continue
        _queue_name, payload = result
        log.info("received job", payload_bytes=len(payload))
        _process_payload(payload)
    return 0


configure_logging(service="worker")
log = get_logger(__name__)


if __name__ == "__main__":
    raise SystemExit(main())
