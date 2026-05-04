"""Untrusted-field sanitizer for Splunk → LLM context.

CLAUDE.md security posture: "untrusted fields from Splunk events pass through
a sanitizer before entering agent context." Wk-6 ships the basic version: strip
C0/C1 control characters (keeping `\\t`, `\\n`, `\\r`), normalize CRLF → LF,
truncate per-field to 4 KB with a marker. Wk-12 hardens to a full
trust-boundary marker framework.

Cluster E (HIGH-10) adds depth + node-count caps to ``walk_and_sanitize`` so
a recursive payload from a misbehaving tool result can't blow the stack or
explode memory. Truncate-with-marker beats raise on the hot path:
``walk_and_sanitize`` is called over OCSF text fields, every tool-result
dict before it lands in graph state, and audit ``details`` payloads — an
exception there would abort the whole investigation over a malformed input,
which is strictly worse than a truncated audit row.

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

#: HIGH-10: cap recursion depth for ``walk_and_sanitize``. 64 is well above
#: any legitimate OCSF / tool-result shape we've seen in BOTS data; deep-nest
#: payloads beyond this collapse to ``_DEPTH_EXCEEDED_MARKER`` rather than
#: raising RecursionError mid-investigation.
_MAX_DEPTH = 64

#: HIGH-10: total node-count cap (across the entire walk, not per-branch).
#: Real tool-result payloads sit well under 1k nodes; 10k gives ample
#: headroom for OCSF-mapped enrichment objects while still bounding worst
#: case at well under a megabyte of post-walk Python.
_MAX_NODES = 10_000

#: Sentinel strings substituted for over-budget subtrees. Stringly-typed so
#: every consumer (audit JSON serialization, prompt rendering, manifest)
#: handles them uniformly.
_DEPTH_EXCEEDED_MARKER = "[depth-exceeded]"
_SIZE_EXCEEDED_MARKER = "[size-exceeded]"

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


def _walk_with_limits(obj: Any, depth: int, node_count: int, *, max_chars: int) -> tuple[Any, int]:
    """Bounded recursion helper for ``walk_and_sanitize``.

    Returns ``(sanitized_obj, updated_node_count)``. On overflow, returns the
    appropriate marker string and a bumped count (so the caller still sees
    progress and short-circuits its own iteration when total budget is
    spent).
    """
    if depth > _MAX_DEPTH:
        return _DEPTH_EXCEEDED_MARKER, node_count + 1
    if node_count >= _MAX_NODES:
        return _SIZE_EXCEEDED_MARKER, node_count + 1

    if isinstance(obj, str):
        return sanitize_untrusted(obj, max_chars=max_chars), node_count + 1

    if isinstance(obj, dict):
        out_dict: dict[Any, Any] = {}
        node_count += 1
        for k, v in obj.items():
            if node_count >= _MAX_NODES:
                out_dict[k] = _SIZE_EXCEEDED_MARKER
                node_count += 1
                break
            sanitized, node_count = _walk_with_limits(v, depth + 1, node_count, max_chars=max_chars)
            out_dict[k] = sanitized
        return out_dict, node_count

    if isinstance(obj, list):
        out_list: list[Any] = []
        node_count += 1
        for v in obj:
            if node_count >= _MAX_NODES:
                out_list.append(_SIZE_EXCEEDED_MARKER)
                node_count += 1
                break
            sanitized, node_count = _walk_with_limits(v, depth + 1, node_count, max_chars=max_chars)
            out_list.append(sanitized)
        return out_list, node_count

    # Numbers, bools, None — pass through unchanged. Tuples/sets/etc fall
    # into this branch by design (out of scope per the OCSF + tool-result
    # shapes we handle); they are not recursed.
    return obj, node_count + 1


def walk_and_sanitize(obj: Any, *, max_chars: int = MAX_FIELD_CHARS) -> Any:
    """Recursively sanitize every string value inside a dict / list.

    Non-string values pass through unchanged (numbers, bools, None). Dicts
    sanitize their string values (keys are NOT sanitized — they're typically
    OCSF schema field names from our own mapper, not Splunk-controlled).
    Lists recurse element-wise. Tuples / sets / other iterables are NOT
    recursed — out of scope for the OCSF + tool-result shapes we handle.

    HIGH-10: bounded by ``_MAX_DEPTH`` + ``_MAX_NODES``. Subtrees that exceed
    either cap are replaced by ``"[depth-exceeded]"`` / ``"[size-exceeded]"``
    rather than raising — sanitizer is on the hot path and a malformed tool
    result must not abort the investigation.
    """
    sanitized, _ = _walk_with_limits(obj, 0, 0, max_chars=max_chars)
    return sanitized


__all__ = ["MAX_FIELD_CHARS", "sanitize_untrusted", "walk_and_sanitize"]
