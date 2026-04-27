"""Unit tests for the untrusted-field sanitizer."""

from __future__ import annotations

import pytest

from sentient_orchestrator.investigation.sanitizer import (
    MAX_FIELD_CHARS,
    sanitize_untrusted,
    walk_and_sanitize,
)

# ------------------------------------------------------------------ scalar


def test_strips_null_byte() -> None:
    assert sanitize_untrusted("hello\x00world") == "helloworld"


def test_strips_bell_and_backspace() -> None:
    assert sanitize_untrusted("a\x07b\x08c") == "abc"


def test_strips_del_char() -> None:
    assert sanitize_untrusted("a\x7fb") == "ab"


def test_strips_c1_controls() -> None:
    assert sanitize_untrusted("x\x80\x9fy") == "xy"


def test_keeps_tab_newline_carriage() -> None:
    """\\t \\n stay; \\r normalized to \\n (CRLF normalization)."""
    assert sanitize_untrusted("a\tb\nc") == "a\tb\nc"


def test_normalizes_crlf_to_lf() -> None:
    assert sanitize_untrusted("a\r\nb\r\nc") == "a\nb\nc"


def test_normalizes_lone_cr_to_lf() -> None:
    assert sanitize_untrusted("a\rb") == "a\nb"


def test_unicode_passthrough() -> None:
    """Unicode printables (à, é, ✓, …) must pass through unchanged."""
    assert sanitize_untrusted("café résumé ✓ …") == "café résumé ✓ …"


def test_truncates_with_marker() -> None:
    long = "x" * (MAX_FIELD_CHARS + 100)
    out = sanitize_untrusted(long)
    assert out.startswith("x" * MAX_FIELD_CHARS)
    assert out.endswith("…[truncated]")
    assert len(out) == MAX_FIELD_CHARS + len("…[truncated]")


def test_no_truncation_when_under_cap() -> None:
    out = sanitize_untrusted("x" * 100)
    assert out == "x" * 100
    assert "[truncated]" not in out


def test_idempotent() -> None:
    raw = "a\x00b\r\nc\tD"
    once = sanitize_untrusted(raw)
    twice = sanitize_untrusted(once)
    assert once == twice


def test_custom_max_chars() -> None:
    out = sanitize_untrusted("abcdefgh", max_chars=4)
    assert out == "abcd…[truncated]"


def test_non_str_input_raises() -> None:
    with pytest.raises(TypeError):
        sanitize_untrusted(123)  # type: ignore[arg-type]


# ----------------------------------------------------------- encoded payloads


def test_base64_passthrough() -> None:
    """base64 has no control chars so it passes unchanged."""
    payload = "SGVsbG8sIFdvcmxkIQ=="
    assert sanitize_untrusted(payload) == payload


def test_hex_string_passthrough() -> None:
    payload = "deadbeef0123456789abcdef"
    assert sanitize_untrusted(payload) == payload


def test_json_string_passthrough() -> None:
    payload = '{"src_ip": "10.0.0.5", "user": "alice"}'
    assert sanitize_untrusted(payload) == payload


def test_splunk_json_with_escaped_quotes() -> None:
    """Real Splunk events often have escaped quotes inside _raw."""
    payload = '_raw="EventCode=4624 SubjectUserName=\\"alice\\""'
    # Backslash + quotes are NOT control chars; must pass through.
    assert sanitize_untrusted(payload) == payload


# ------------------------------------------------------------------ walk


def test_walk_dict_sanitizes_string_values() -> None:
    raw = {"ok": "value\x00bad", "n": 42, "b": True}
    out = walk_and_sanitize(raw)
    assert out == {"ok": "valuebad", "n": 42, "b": True}


def test_walk_dict_does_not_sanitize_keys() -> None:
    """Keys are OCSF schema field names — not Splunk-controlled. Don't strip."""
    raw = {"src_ip": "1.2.3.4"}
    out = walk_and_sanitize(raw)
    assert "src_ip" in out


def test_walk_nested() -> None:
    raw = {"a": {"b": "x\x07y", "c": [1, "z\x08w"]}}
    out = walk_and_sanitize(raw)
    assert out == {"a": {"b": "xy", "c": [1, "zw"]}}


def test_walk_list_of_strings() -> None:
    raw = ["a\x00b", "c", "d\x07e"]
    out = walk_and_sanitize(raw)
    assert out == ["ab", "c", "de"]


def test_walk_passes_through_non_str_scalars() -> None:
    assert walk_and_sanitize(42) == 42
    assert walk_and_sanitize(3.14) == 3.14
    assert walk_and_sanitize(True) is True
    assert walk_and_sanitize(None) is None


def test_walk_truncates_strings() -> None:
    long = "y" * (MAX_FIELD_CHARS + 50)
    out = walk_and_sanitize({"f": long})
    assert isinstance(out, dict)
    assert out["f"].endswith("…[truncated]")


def test_walk_custom_max_chars_propagates() -> None:
    out = walk_and_sanitize({"f": "abcdef"}, max_chars=3)
    assert out == {"f": "abc…[truncated]"}
