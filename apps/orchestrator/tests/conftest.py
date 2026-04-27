"""Pytest fixtures for the orchestrator package.

The verify smoke needs three live resources: Postgres (for `PostgresSaver`),
OpenRouter (for the LLM), and a Python interpreter (for the stdio echo server).
We skip cleanly when any are missing or when the env vars carry the
`.env.example` placeholder values.
"""

from __future__ import annotations

import os

import pytest


def _is_placeholder(value: str) -> bool:
    return value.startswith("CHANGEME_") or not value


@pytest.fixture
def require_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if _is_placeholder(url):
        pytest.skip("DATABASE_URL missing — smoke needs Postgres")
    return url


@pytest.fixture
def require_openrouter_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if _is_placeholder(key):
        pytest.skip(
            "OPENROUTER_API_KEY missing or placeholder — smoke needs live OpenRouter"
        )
    return key
