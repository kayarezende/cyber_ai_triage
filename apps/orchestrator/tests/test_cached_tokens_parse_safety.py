"""Cluster E MED-12: cached_tokens parse never converts a 200 into validation_fail.

OpenRouter normally returns ``usage.prompt_tokens_details.cached_tokens`` as
a non-negative int. A misbehaving provider could return a string ``"n/a"``,
``null``, or even a nested dict. The pre-fix ``int(details.get(...))`` raised,
which the router classified as ``validation_fail`` — burning a perfectly good
HTTP call. New behaviour: try/except around the parse, default 0, log warning.
"""

from __future__ import annotations

from sentient_orchestrator.llm.openrouter import _parse_response


def _payload(cached_value: object) -> dict[str, object]:
    return {
        "id": "gen-1",
        "model": "anthropic/claude-sonnet-4-6",
        "choices": [
            {
                "message": {"content": "ok", "tool_calls": None},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": cached_value},
            "cost": 0.0001,
        },
    }


def test_normal_cached_int_passthrough() -> None:
    resp = _parse_response(_payload(50), latency_ms=42)
    assert resp.cached_tokens == 50


def test_string_cached_defaults_to_zero() -> None:
    resp = _parse_response(_payload("n/a"), latency_ms=42)
    assert resp.cached_tokens == 0


def test_dict_cached_defaults_to_zero() -> None:
    resp = _parse_response(_payload({"nested": 1}), latency_ms=42)
    assert resp.cached_tokens == 0


def test_none_cached_defaults_to_zero() -> None:
    resp = _parse_response(_payload(None), latency_ms=42)
    assert resp.cached_tokens == 0


def test_missing_details_block_defaults_to_zero() -> None:
    payload = {
        "id": "gen-1",
        "model": "test",
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "cost": 0.0001},
    }
    resp = _parse_response(payload, latency_ms=42)
    assert resp.cached_tokens == 0


def test_details_not_a_dict_defaults_to_zero() -> None:
    """If details isn't a dict at all, no parse attempt — silent zero."""
    payload = {
        "id": "gen-1",
        "model": "test",
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_tokens_details": "not-a-dict",
            "cost": 0.0001,
        },
    }
    resp = _parse_response(payload, latency_ms=42)
    assert resp.cached_tokens == 0


def test_string_numeric_cached_parses_normally() -> None:
    """int(str_int) works — a provider returning '50' instead of 50 still fine."""
    resp = _parse_response(_payload("50"), latency_ms=42)
    assert resp.cached_tokens == 50
