"""LangSmith tracing init (ADR 0013).

Gated on both LANGSMITH_TRACING truthy AND LANGSMITH_API_KEY looking real
(starts with `ls__`, per LangSmith's own convention) — the .env.example ships a
`CHANGEME_ls__...` placeholder that must NOT trigger a network probe on boot.
"""

from __future__ import annotations

import os

from sentient_common.logging import get_logger

log = get_logger(__name__)

_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def _is_tracing_requested() -> bool:
    return os.environ.get("LANGSMITH_TRACING", "").lower() in _TRUTHY


def _has_real_key() -> bool:
    key = os.environ.get("LANGSMITH_API_KEY", "")
    return key.startswith("ls__")


def init_tracing() -> bool:
    """Return True if tracing is enabled + reachable, else False.

    Never raises — boot must not be killed by LangSmith being down.
    """
    if not _is_tracing_requested():
        log.info("langsmith disabled", reason="tracing_off")
        return False

    if not _has_real_key():
        log.info("langsmith disabled", reason="no_key")
        return False

    project = os.environ.get("LANGSMITH_PROJECT", "default")
    try:
        from langsmith import Client

        # Construct the client — raises on malformed key. Deeper liveness
        # probe (project existence) happens on first trace in wk 6.
        Client()
    except Exception as exc:
        log.warning(
            "langsmith client init failed, continuing without tracing",
            error=str(exc),
        )
        return False

    log.info("langsmith tracing enabled", project=project)
    return True
