"""Cluster E HIGH-10: walk_and_sanitize depth + node-count caps.

A recursive-bomb tool result must not blow the stack or explode memory. The
public API truncates over-budget subtrees with sentinel markers rather than
raising, because the sanitizer is on the hot path (audit emit + prompt build
+ tools_node) and a malformed input must not abort the investigation.
"""

from __future__ import annotations

from sentient_orchestrator.investigation.sanitizer import (
    _DEPTH_EXCEEDED_MARKER,
    _MAX_DEPTH,
    _MAX_NODES,
    _SIZE_EXCEEDED_MARKER,
    walk_and_sanitize,
)


def _nest(depth: int) -> dict[str, object]:
    """Build a dict nested ``depth`` levels deep at key ``"k"``."""
    out: dict[str, object] = {}
    cur: dict[str, object] = out
    for _ in range(depth):
        nxt: dict[str, object] = {}
        cur["k"] = nxt
        cur = nxt
    cur["leaf"] = "ok"
    return out


def test_under_limit_passthrough() -> None:
    nested = _nest(8)
    out = walk_and_sanitize(nested)
    cur = out
    for _ in range(8):
        assert isinstance(cur, dict)
        cur = cur["k"]
    assert cur == {"leaf": "ok"}


def test_deep_nest_replaces_with_depth_marker() -> None:
    """Source nests 114 levels; walker truncates at _MAX_DEPTH+1 with marker."""
    nested = _nest(_MAX_DEPTH + 50)
    out = walk_and_sanitize(nested)
    cur: object = out
    depth_walked = 0
    while isinstance(cur, dict) and "k" in cur:
        cur = cur["k"]
        depth_walked += 1
        if depth_walked > _MAX_DEPTH + 10:
            raise AssertionError("walker did not truncate at expected depth")
    assert cur == _DEPTH_EXCEEDED_MARKER
    # Truncation at depth _MAX_DEPTH+1 (one level below the last good dict).
    assert depth_walked == _MAX_DEPTH + 1


def test_wide_dict_replaces_with_size_marker() -> None:
    wide = {f"k{i}": f"v{i}" for i in range(_MAX_NODES + 500)}
    out = walk_and_sanitize(wide)
    assert isinstance(out, dict)
    assert _SIZE_EXCEEDED_MARKER in out.values()
    assert len(out) <= _MAX_NODES + 5


def test_wide_list_replaces_with_size_marker() -> None:
    wide = list(range(_MAX_NODES + 500))
    out = walk_and_sanitize(wide)
    assert isinstance(out, list)
    assert _SIZE_EXCEEDED_MARKER in out
    assert len(out) <= _MAX_NODES + 5


def test_total_node_budget_is_global() -> None:
    """_MAX_NODES is global, not per-branch — many shallow branches still cap."""
    payload = {f"branch{i}": list(range(200)) for i in range(_MAX_NODES // 100)}
    out = walk_and_sanitize(payload)
    flat: list[object] = []

    def collect(o: object) -> None:
        if isinstance(o, dict):
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
        else:
            flat.append(o)

    collect(out)
    assert _SIZE_EXCEEDED_MARKER in flat


def test_under_limit_string_unchanged() -> None:
    assert walk_and_sanitize("hello") == "hello"


def test_under_limit_list_unchanged() -> None:
    assert walk_and_sanitize([1, 2, 3]) == [1, 2, 3]


def test_under_limit_primitive_passthrough() -> None:
    assert walk_and_sanitize(42) == 42
    assert walk_and_sanitize(None) is None
    assert walk_and_sanitize(True) is True


def test_strings_inside_walk_are_sanitized() -> None:
    """Control chars stripped through nested walk."""
    payload = {"a": "ok\x00bad", "b": ["nested\x07", "clean"]}
    out = walk_and_sanitize(payload)
    assert out == {"a": "okbad", "b": ["nested", "clean"]}
