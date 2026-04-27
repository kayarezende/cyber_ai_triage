"""ChatOpenAI factory pointed at OpenRouter.

`langchain-openai` 1.x emits a deprecation-style warning when `base_url` points
at a non-OpenAI provider (OpenRouter, vLLM, DeepSeek). Wk-2 accepts the warning:
ADR-0015's `LLMRouter` (lands wk 5) bypasses LangChain entirely and goes direct
httpx for the production audit ledger. Our LangChain coupling is bounded to this
verify harness + the wk-6 graph's `bind_tools` plumbing.

Default model is the wk-2 dev model from `tasks/todo.md`. Production defaults
(seed-row driven) are Opus 4.7 / Sonnet 4.6 / Haiku 4.5; not relevant here.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_openai import ChatOpenAI

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_VERIFY_MODEL = "google/gemini-3-flash-preview"


def build_chat_openrouter(
    *, model: str = DEFAULT_VERIFY_MODEL, **overrides: Any
) -> ChatOpenAI:
    """Build a ChatOpenAI pointed at OpenRouter.

    `temperature=0` and `max_retries=0` make verify-harness behaviour
    deterministic — failures are loud, no silent retries, no sampling drift.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        msg = "OPENROUTER_API_KEY missing — cannot run verify against live OpenRouter"
        raise RuntimeError(msg)

    kwargs: dict[str, Any] = {
        "model": model,
        "api_key": api_key,
        "base_url": OPENROUTER_BASE_URL,
        "default_headers": {
            "HTTP-Referer": "https://sentientlayer.ai",
            "X-Title": "Sentient Layer (verify)",
        },
        "temperature": 0,
        "max_retries": 0,
        "timeout": 30.0,
    }
    kwargs.update(overrides)
    return ChatOpenAI(**kwargs)
