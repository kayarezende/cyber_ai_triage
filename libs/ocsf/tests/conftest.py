"""Shared pytest fixtures for libs/ocsf tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "splunk_notables"


@pytest.fixture
def load_notable() -> Callable[[str], dict[str, Any]]:
    """Load a canned Splunk notable fixture by base name (no `.json` suffix)."""

    def _load(name: str) -> dict[str, Any]:
        path = _FIXTURE_DIR / f"{name}.json"
        return json.loads(path.read_text())

    return _load
