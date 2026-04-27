"""Tests for sentient_common.logging (structlog JSON pipeline)."""

from __future__ import annotations

import json
import logging

import pytest

from sentient_common.logging import configure_logging, get_logger


def test_configure_emits_json_with_service_field(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(service="test-svc", level="DEBUG")
    get_logger("tests").info("hello", answer=42)

    captured = capsys.readouterr().out.strip().splitlines()
    assert captured, "expected at least one log line"

    payload = json.loads(captured[-1])
    assert payload["service"] == "test-svc"
    assert payload["event"] == "hello"
    assert payload["answer"] == 42
    assert payload["level"] == "info"
    assert "timestamp" in payload


def test_stdlib_logger_also_json_routed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(service="bridge-test", level="INFO")
    logging.getLogger("some.third.party").warning("boom %s", "value")

    captured = capsys.readouterr().out.strip().splitlines()
    assert captured, "expected at least one log line"

    payload = json.loads(captured[-1])
    assert payload["service"] == "bridge-test"
    assert payload["level"] == "warning"
    assert "boom" in payload["event"]
