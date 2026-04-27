"""Untrusted-field sanitizer for Splunk → LLM context.

CLAUDE.md security posture: "untrusted fields from Splunk events pass through
a sanitizer before entering agent context." Wk-6 ships the basic version: strip
C0/C1 control characters (keeping `\\t`, `\\n`, `\\r`), normalize CRLF → LF,
truncate per-field to 4 KB with a marker. Wk-12 hardens to a full
trust-boundary marker framework.

Applied at three touchpoints (see plan §Sanitizer design):
  1. `prompt.build_initial_user_message` — over OCSF text fields, triage
     reasoning, entity lists.
  2. `nodes.tools_node` — over each tool result before adding the
     ToolMessage content to graph state.
  3. `audit.emit_tool_call` — over args + result summaries before INSERT.

Narrow regex on purpose: encoded payloads (base64, hex, JSON-escaped) must
pass through unchanged.
"""

from __future__ import annotations

import re
from typing import Any

#: Per-field cap before truncation. Generous enough to carry a typical
#: ToolMessage payload but small enough to keep prompts bounded across
#: ~10 tool calls.
MAX_FIELD_CHARS = 4000

#: Truncation marker appended after `[:max_chars]` slice.
_TRUNCATION_MARKER = "…[truncated]"

#: Strip C0 (0x00–0x1F) + DEL (0x7F) + C1 (0x80–0x9F).
#: Keep `\t` (0x09), `\n` (0x0A), `\r` (0x0D). Anything outside C0/C1
#: passes through unchanged — Unicode printables, encoded payloads,
#: JSON-escaped strings.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize_untrusted(value: str, *, max_chars: int = MAX_FIELD_CHARS) -> str:
    """Strip control chars, normalize CRLF→LF, truncate w/ marker.

    Idempotent: applying twice yields the same result as once.
    """
    if not isinstance(value, str):
        msg = f"sanitize_untrusted requires str, got {type(value).__name__}"
        raise TypeError(msg)
    # Normalize line endings first so `\r\n` collapses to `\n` rather than
    # leaving a lone `\r` after control-char strip.
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _CONTROL_CHARS_RE.sub("", normalized)
    if len(cleaned) > max_chars:
        return cleaned[:max_chars] + _TRUNCATION_MARKER
    return cleaned


def walk_and_sanitize(obj: Any, *, max_chars: int = MAX_FIELD_CHARS) -> Any:
    """Recursively sanitize every string value inside a dict / list.

    Non-string values pass through unchanged (numbers, bools, None). Dicts
    sanitize their string values (keys are NOT sanitized — they're typically
    OCSF schema field names from our own mapper, not Splunk-controlled).
    Lists recurse element-wise. Tuples / sets / other iterables are NOT
    recursed — out of scope for the OCSF + tool-result shapes we handle.
    """
    if isinstance(obj, str):
        return sanitize_untrusted(obj, max_chars=max_chars)
    if isinstance(obj, dict):
        return {k: walk_and_sanitize(v, max_chars=max_chars) for k, v in obj.items()}
    if isinstance(obj, list):
        return [walk_and_sanitize(v, max_chars=max_chars) for v in obj]
    return obj


__all__ = ["MAX_FIELD_CHARS", "sanitize_untrusted", "walk_and_sanitize"]
