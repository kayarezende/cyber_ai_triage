"""LangSmith tracing init (ADR 0013).

Gated on both LANGSMITH_TRACING truthy AND LANGSMITH_API_KEY looking real (a
non-empty value that isn't the `.env.example` `CHANGEME_*` placeholder). We
accept both the older `ls__` and current `lsv2_` LangSmith key prefixes, plus
any other non-CHANGEME value (LangSmith Hub keys, self-hosted, etc.).

When tracing is enabled, this module also exports `LANGCHAIN_TRACING_V2` and
`LANGCHAIN_PROJECT` into the process env. LangChain's runnables (incl.
`ChatOpenAI` + `bind_tools`) read those legacy `LANGCHAIN_*` env vars when
deciding whether to ship traces. Setting only `LANGSMITH_TRACING` is not
enough — without `LANGCHAIN_TRACING_V2=true` the LangSmith dashboard shows
no runs even though `Client()` initialised cleanly.
"""

from __future__ import annotations

import os

from sentient_common.logging import get_logger

log = get_logger(__name__)

_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})

# Real LangSmith API keys ship with one of these prefixes today; we also
# accept anything else that isn't an obvious placeholder so self-hosted /
# Hub keys aren't rejected.
_KNOWN_KEY_PREFIXES: tuple[str, ...] = ("ls__", "lsv2_")


def _is_tracing_requested() -> bool:
    return os.environ.get("LANGSMITH_TRACING", "").lower() in _TRUTHY


def _has_real_key() -> bool:
    key = os.environ.get("LANGSMITH_API_KEY", "")
    if not key:
        return False
    if key.startswith("CHANGEME_"):
        return False
    # Allow ls__ / lsv2_ explicitly + any other non-placeholder value.
    return any(key.startswith(p) for p in _KNOWN_KEY_PREFIXES) or len(key) >= 20


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

    # Propagate to LangChain's legacy env vars so `ChatOpenAI` etc. ship
    # traces. LangSmith SDK + LangChain read different env names.
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_PROJECT", project)

    log.info("langsmith tracing enabled", project=project)
    return True
