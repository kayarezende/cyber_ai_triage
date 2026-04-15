"""Structlog JSON logging for Sentient Layer services.

Every service's entrypoint calls `configure_logging(service="<name>")` once.
After that, any `structlog.get_logger()` or stdlib `logging.getLogger()` call
emits a single JSON line per record to stdout, including a `service` field.

Docker captures stdout into container logs; `docker compose logs | jq` gives a
queryable stream without any extra log-forwarding infra in MVP.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def _add_service(service: str) -> Processor:
    def processor(
        _logger: logging.Logger, _method_name: str, event_dict: EventDict
    ) -> EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    return processor


def configure_logging(service: str, level: str = "INFO") -> None:
    """Configure structlog + stdlib logging to emit JSON to stdout.

    Idempotent: re-configuring overrides prior state (handy in tests).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _add_service(service),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # Quiet the noisiest third-party loggers; keep at WARNING unless caller overrides.
    for name in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> Any:
    """Thin wrapper so callers don't import structlog directly."""
    return structlog.get_logger(name)
