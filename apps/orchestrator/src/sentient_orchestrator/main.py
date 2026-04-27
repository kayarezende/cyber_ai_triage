"""Orchestrator entrypoint (stub).

Wk 1: sentinel heartbeat + LangSmith init + structured logging.
Wk 6: becomes the LangGraph StateGraph runner pulling jobs from Redis and
checkpointing to Postgres.
"""

from __future__ import annotations

import signal
import time
from pathlib import Path
from types import FrameType

from sentient_common.logging import configure_logging, get_logger
from sentient_orchestrator.tracing import init_tracing

_SENTINEL = Path("/tmp/ready")
_HEARTBEAT_SECONDS = 30

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    _shutdown = True
    log.info("orchestrator shutting down", signal=signum)


def main() -> int:
    init_tracing()
    log.info("orchestrator ready", note="awaiting wk 6 StateGraph")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not _shutdown:
        _SENTINEL.touch()
        for _ in range(_HEARTBEAT_SECONDS):
            if _shutdown:
                break
            time.sleep(1)
    return 0


configure_logging(service="orchestrator")
log = get_logger(__name__)


if __name__ == "__main__":
    raise SystemExit(main())
