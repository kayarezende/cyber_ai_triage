"""Unit tests for Tier-2 investigation graph nodes.

Mocks `LLMRouter` + `tenant_session` + tools so nodes can be exercised
without DB or live OpenRouter. Asserts state deltas, audit emissions, and
control-char sanitization.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from langchain_core.tools import tool

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation.nodes import (
    agent_node,
    correlate_node,
    draft_verdict_node,
    plan_node,
    reset_node_call_counts,
    route_after_agent,
    tools_node,
    tools_to_openai_schema,
)
from sentient_orchestrator.investigation.state import (
    MAX_TOOL_CALLS,
    InvestigationOutput,
)
from sentient_orchestrator.llm.openrouter import OpenRouterToolCall
from sentient_orchestrator.llm.router import LLMResult

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")


# ------------------------------------------------------------------ helpers


def _llm_result(
    *,
    content: str = "",
    parsed: object = None,
    tool_calls: tuple[OpenRouterToolCall, ...] = (),
    model: str = "google/gemini-3-flash-preview",
) -> LLMResult:
    return LLMResult(
        content=content,
        parsed=parsed,  # type: ignore[arg-type]
        model_requested=model,
        model_used=model,
        attempt_num=1,
        input_tokens=10,
        output_tokens=5,
        cached_tokens=0,
        cost_usd=0.0001,
        latency_ms=42,
        tool_calls=tool_calls,
    )


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    """Drop-in replacement for sentient_common.db.tenant_session."""
    yield MagicMock()


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@pytest.fixture
def patched_llm(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch LLMRouter + tenant_session in the nodes module."""
    captured: dict[str, Any] = {"calls": []}

    class _FakeRouter:
        def __init__(self, _tenant_id: UUID, _conn: object) -> None:
            pass

        async def call(
            self,
            *,
            role: str,
            messages: list[dict[str, Any]],
            response_schema: object = None,
            investigation_id: UUID | None = None,
            tools: list[dict[str, Any]] | None = None,
            tool_choice: str | dict[str, Any] | None = None,
        ) -> LLMResult:
            captured["calls"].append(
                {
                    "role": role,
                    "messages": list(messages),
                    "response_schema": response_schema,
                    "tools": tools,
                    "tool_choice": tool_choice,
                }
            )
            return captured["next_result"]

    monkeypatch.setattr(nodes, "LLMRouter", _FakeRouter)
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    captured["next_result"] = _llm_result(content="ok")
    return captured


@pytest.fixture
def emit_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            calls.append((name, kwargs))

        return _f

    monkeypatch.setattr(nodes.audit, "emit_llm_call", _track("llm_call"))
    monkeypatch.setattr(nodes.audit, "emit_tool_call", _track("tool_call"))
    monkeypatch.setattr(nodes.audit, "emit_verdict_drafted", _track("verdict_drafted"))
    return calls


def _config(
    *,
    finding: object | None = None,
    tools: list[Any] | None = None,
    mitre_descs: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "configurable": {
            "tenant_id": str(TENANT),
            "investigation_id": str(INV),
            "finding": finding,
            "tools": tools or [],
            "mitre_descs": mitre_descs or {},
        }
    }


# ------------------------------------------------------------- routing


def test_route_after_agent_with_tool_calls_routes_to_tools() -> None:
    state = {
        "messages": [{"role": "assistant", "content": "", "tool_calls": [{"id": "a"}]}],
        "tool_call_count": 1,
    }
    assert route_after_agent(state) == "tools"  # type: ignore[arg-type]


def test_route_after_agent_no_tool_calls_routes_to_correlate() -> None:
    state = {
        "messages": [{"role": "assistant", "content": "I'm done."}],
        "tool_call_count": 0,
    }
    assert route_after_agent(state) == "correlate"  # type: ignore[arg-type]


def test_route_after_agent_caps_at_max_tool_calls() -> None:
    state = {
        "messages": [{"role": "assistant", "content": "", "tool_calls": [{"id": "x"}]}],
        "tool_call_count": MAX_TOOL_CALLS,
    }
    assert route_after_agent(state) == "correlate"  # type: ignore[arg-type]


def test_route_after_agent_empty_messages_routes_to_correlate() -> None:
    assert route_after_agent({"messages": []}) == "correlate"  # type: ignore[arg-type]


# ------------------------------------------------------------- plan_node


@pytest.mark.asyncio
async def test_plan_node_emits_system_and_user_messages(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    from sentient_ocsf.splunk_mapper import map_notable_to_ocsf

    finding = map_notable_to_ocsf(
        {"search_name": "T", "urgency": "high", "_time": "1700000000.000"},
        finding_uid="fid-plan",
    )
    state = {
        "triage_severity": "high",
        "triage_confidence": 80,
        "triage_mitre_guesses": ["T1110"],
        "triage_entities": ["alice"],
        "triage_reasoning": "x",
    }
    config = _config(finding=finding, mitre_descs={"T1110": "Brute Force"})
    patched_llm["next_result"] = _llm_result(content="plan: pivot on alice")

    delta = await plan_node(state, config=config)  # type: ignore[arg-type]

    msgs = delta["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[1]["role"] == "user"
    assert msgs[2]["role"] == "assistant"
    assert delta["tool_call_count"] == 0
    assert nodes.node_call_counts["plan"] == 1
    assert any(name == "llm_call" for name, _ in emit_calls)


# ------------------------------------------------------------- agent_node


@pytest.mark.asyncio
async def test_agent_node_passes_tools_and_serializes_tool_calls(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    @tool
    def siem_query(spl: str, earliest: str = "-1h", latest: str = "now") -> str:
        """Run an SPL query."""
        return "{}"

    state = {"messages": [{"role": "user", "content": "ok"}], "tool_call_count": 0}
    patched_llm["next_result"] = _llm_result(
        content="",
        tool_calls=(
            OpenRouterToolCall(
                id="call_1", name="siem_query", arguments={"spl": "index=main"}
            ),
        ),
    )

    config = _config(tools=[siem_query])
    delta = await agent_node(state, config=config)  # type: ignore[arg-type]

    captured = patched_llm["calls"][0]
    assert captured["tool_choice"] == "auto"
    assert captured["tools"] is not None
    assert len(captured["tools"]) == 1

    assistant = delta["messages"][-1]
    assert assistant["role"] == "assistant"
    tcs = assistant["tool_calls"]
    assert len(tcs) == 1
    assert tcs[0]["function"]["name"] == "siem_query"
    # Arguments serialized as JSON string (OpenAI wire format).
    assert tcs[0]["function"]["arguments"] == '{"spl": "index=main"}'
    assert delta["tool_call_count"] == 1
    assert nodes.node_call_counts["agent"] == 1


@pytest.mark.asyncio
async def test_agent_node_no_tool_calls_returns_plain_assistant(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    state = {"messages": [{"role": "user", "content": "x"}], "tool_call_count": 0}
    patched_llm["next_result"] = _llm_result(content="I have enough evidence.")

    config = _config(tools=[])
    delta = await agent_node(state, config=config)  # type: ignore[arg-type]

    assistant = delta["messages"][-1]
    assert assistant["role"] == "assistant"
    assert "tool_calls" not in assistant
    assert delta["tool_call_count"] == 0


# ------------------------------------------------------------- tools_node


@pytest.mark.asyncio
async def test_tools_node_dispatches_and_sanitizes_results(
    monkeypatch: pytest.MonkeyPatch, emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    @tool
    async def siem_query(spl: str = "") -> str:
        """SPL query."""
        return "result\x00with\x07nulls"

    state = {
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "siem_query",
                            "arguments": '{"spl": "index=main"}',
                        },
                    }
                ],
            }
        ]
    }
    config = _config(tools=[siem_query])
    delta = await tools_node(state, config=config)  # type: ignore[arg-type]

    msgs = delta["messages"]
    assert len(msgs) == 1
    assert msgs[0]["role"] == "tool"
    assert msgs[0]["tool_call_id"] == "call_1"
    # Control chars stripped.
    assert msgs[0]["content"] == "resultwithnulls"
    assert nodes.node_call_counts["tools"] == 1
    # One audit emission per tool call.
    tool_emits = [c for name, c in emit_calls if name == "tool_call"]
    assert len(tool_emits) == 1
    assert tool_emits[0]["tool_name"] == "siem_query"


@pytest.mark.asyncio
async def test_tools_node_handles_missing_tool(
    monkeypatch: pytest.MonkeyPatch, emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    @tool
    async def siem_query(spl: str = "") -> str:
        """SPL query."""
        return "ok"

    state = {
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_x",
                        "type": "function",
                        "function": {"name": "unknown_tool", "arguments": "{}"},
                    }
                ],
            }
        ]
    }
    delta = await tools_node(state, config=_config(tools=[siem_query]))  # type: ignore[arg-type]
    assert delta["messages"][0]["content"].startswith("error: tool 'unknown_tool'")


@pytest.mark.asyncio
async def test_tools_node_sanitizes_name_in_missing_tool_error(
    monkeypatch: pytest.MonkeyPatch, emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    """Defence-in-depth: model-emitted tool name with control chars must be
    stripped before echoing back into the LLM context."""
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    @tool
    async def siem_query(spl: str = "") -> str:
        """SPL query."""
        return "ok"

    state = {
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_y",
                        "type": "function",
                        "function": {
                            "name": "evil\x00tool\x07name",
                            "arguments": "{}",
                        },
                    }
                ],
            }
        ]
    }
    delta = await tools_node(state, config=_config(tools=[siem_query]))  # type: ignore[arg-type]
    content = delta["messages"][0]["content"]
    # Control chars stripped from the echoed tool name.
    assert "\x00" not in content
    assert "\x07" not in content
    assert "eviltoolname" in content


@pytest.mark.asyncio
async def test_tools_node_dispatches_multiple_calls(
    monkeypatch: pytest.MonkeyPatch, emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    @tool
    async def siem_query(spl: str = "") -> str:
        """SPL query."""
        return f"result for {spl}"

    state = {
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {
                            "name": "siem_query",
                            "arguments": '{"spl": "a"}',
                        },
                    },
                    {
                        "id": "call_b",
                        "type": "function",
                        "function": {
                            "name": "siem_query",
                            "arguments": '{"spl": "b"}',
                        },
                    },
                ],
            }
        ]
    }
    delta = await tools_node(state, config=_config(tools=[siem_query]))  # type: ignore[arg-type]
    assert len(delta["messages"]) == 2
    assert delta["messages"][0]["tool_call_id"] == "call_a"
    assert delta["messages"][1]["tool_call_id"] == "call_b"


@pytest.mark.asyncio
async def test_tools_node_captures_tool_exceptions_as_error_text(
    monkeypatch: pytest.MonkeyPatch, emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    @tool
    async def siem_query(spl: str = "") -> str:
        """SPL query."""
        msg = "splunk down"
        raise RuntimeError(msg)

    state = {
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_c",
                        "type": "function",
                        "function": {"name": "siem_query", "arguments": "{}"},
                    }
                ],
            }
        ]
    }
    delta = await tools_node(state, config=_config(tools=[siem_query]))  # type: ignore[arg-type]
    content = delta["messages"][0]["content"]
    assert "RuntimeError" in content
    assert "splunk down" in content


# ------------------------------------------------------------- correlate_node


@pytest.mark.asyncio
async def test_correlate_node_appends_summary_message(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    state = {"messages": [{"role": "user", "content": "evidence"}]}
    patched_llm["next_result"] = _llm_result(content="confirmed T1110.")

    delta = await correlate_node(state, config=_config())  # type: ignore[arg-type]

    msgs = delta["messages"]
    # Synthetic correlate user prompt + assistant response.
    assert msgs[0]["role"] == "user"
    assert "Summarize the evidence" in msgs[0]["content"]
    assert msgs[1]["role"] == "assistant"
    assert "T1110" in msgs[1]["content"]


# ------------------------------------------------------------- draft_verdict_node


@pytest.mark.asyncio
async def test_draft_verdict_node_returns_parsed_output(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    parsed = InvestigationOutput(
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1110"],
        summary="Brute force confirmed.",
        evidence=["spl: index=main user=alice failed_count>10"],
        reasoning="Many failures from one IP, then one success.",
    )
    patched_llm["next_result"] = _llm_result(
        content=parsed.model_dump_json(), parsed=parsed
    )

    state = {"messages": [{"role": "user", "content": "evidence"}]}
    delta = await draft_verdict_node(state, config=_config())  # type: ignore[arg-type]

    assert delta["draft_verdict"]["verdict"] == "true_positive"
    assert delta["draft_verdict"]["mitre_techniques"] == ["T1110"]
    # Schema retry mode used (response_schema set, tools unset).
    captured = patched_llm["calls"][0]
    assert captured["response_schema"] is InvestigationOutput
    assert captured["tools"] is None
    # verdict_drafted audit row emitted.
    assert any(name == "verdict_drafted" for name, _ in emit_calls)


@pytest.mark.asyncio
async def test_draft_verdict_node_rejects_unparsed_result(
    patched_llm: dict[str, Any], emit_calls: list[tuple[str, dict[str, Any]]]
) -> None:
    """If LLMRouter exhausts validation retries it raises FallbackChainExhausted;
    if it ever returns a result with parsed=None, we treat that as a bug."""
    patched_llm["next_result"] = _llm_result(content="", parsed=None)
    with pytest.raises(RuntimeError, match="parsed InvestigationOutput"):
        await draft_verdict_node(
            {"messages": []}, config=_config()  # type: ignore[arg-type]
        )


# ------------------------------------------------------------- helpers


def test_tools_to_openai_schema() -> None:
    @tool
    def siem_query(spl: str) -> str:
        """SPL search."""
        return ""

    schema = tools_to_openai_schema([siem_query])
    assert len(schema) == 1
    fn = schema[0]
    assert fn["type"] == "function"
    assert fn["function"]["name"] == "siem_query"


def test_extract_tool_text_from_content_blocks() -> None:
    blocks = [
        {"type": "text", "text": "hello"},
        {"type": "text", "text": " world"},
    ]
    assert nodes.extract_tool_text(blocks) == "hello world"


def test_extract_tool_text_passthrough_string() -> None:
    assert nodes.extract_tool_text("plain") == "plain"


def test_extract_tool_text_falls_back_to_str() -> None:
    assert nodes.extract_tool_text(42) == "42"


def test_inject_failure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INVESTIGATION_INJECT_FAILURE", "plan")
    with pytest.raises(RuntimeError, match="simulated failure in plan"):
        nodes._maybe_inject_failure("plan")


def test_serialize_assistant_message_emits_json_string_args() -> None:
    """Confirm tool_calls.arguments goes back over the wire as a JSON STRING."""
    result = _llm_result(
        tool_calls=(
            OpenRouterToolCall(id="x", name="t", arguments={"a": 1, "b": [2, 3]}),
        )
    )
    msg = nodes._serialize_assistant_message("hi", result)
    args = msg["tool_calls"][0]["function"]["arguments"]
    assert isinstance(args, str)
    assert json.loads(args) == {"a": 1, "b": [2, 3]}
