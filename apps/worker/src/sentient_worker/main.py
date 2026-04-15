"""Worker entrypoint (stub).

Wk 1: BLPOP loop + sentinel heartbeat + structured logging.
Wk 4: queue consumer that invokes orchestrator per investigation job.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path
from types import FrameType
from typing import cast

import redis
from sentient_common.logging import configure_logging, get_logger

_SENTINEL = Path("/tmp/ready")
_QUEUE = "sentient:jobs:investigations"
_BLPOP_TIMEOUT_SECONDS = 30

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    _shutdown = True
    log.info("worker shutting down", signal=signum)


def main() -> int:
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    client = redis.Redis.from_url(url)
    log.info("worker ready", queue=_QUEUE, note="awaiting wk 4 handler")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not _shutdown:
        _SENTINEL.touch()
        result = cast(
            "tuple[bytes, bytes] | None",
            client.blpop([_QUEUE], timeout=_BLPOP_TIMEOUT_SECONDS),
        )
        if result is None:
            continue
        _queue_name, payload = result
        log.info("received job", payload_bytes=len(payload))
        # wk 4: dispatch to orchestrator; for now, drop on the floor.
    return 0


configure_logging(service="worker")
log = get_logger(__name__)


if __name__ == "__main__":
    raise SystemExit(main())
