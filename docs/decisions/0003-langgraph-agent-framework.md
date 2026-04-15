# 0003: LangGraph as the agent framework

Date: 2026-04-15
Status: Accepted

## Context

MVP needs a Python agent framework that:
- Runs multi-turn investigations with MCP tool calls.
- Supports human-in-loop analyst approval (pause mid-investigation, resume on click).
- Persists mid-run state so a container crash doesn't lose a 5-minute investigation.
- Has headroom for future multi-agent patterns (specialist agents: phishing, insider threat, ransomware).
- Works with Claude models today and can swap in on-prem / Gemini / GPT later.
- Has MCP support.

## Decision

**LangGraph** + `langchain-anthropic` (and/or `langchain-openai` for OpenRouter) + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`.

Investigation is modeled as a `StateGraph` with nodes: `plan → execute_tools → correlate → apply_detection_rules → draft_verdict → review → await_approval → writeback`. `PostgresSaver` checkpointer snapshots state at every node. `interrupt()` at `await_approval` pauses the graph; analyst approval from UI resumes it.

## Alternatives considered

- **Claude Agent SDK** — Claude-only, no on-prem runway. Rejected for vendor lock-in + future flexibility.
- **Pydantic AI** — lighter deps, stronger type safety, but no native HITL `interrupt()` or checkpointing. Would require ~1 week DIY plumbing for HITL. Strong candidate; LangGraph won on HITL + checkpointing being first-class.
- **OpenAI Agents SDK** — OpenAI-first, aesthetic dissonance with "never OpenAI for customer data" positioning; less mature than LangGraph for multi-turn agent work.
- **LangChain (old `AgentExecutor`)** — deprecated by LangChain's own team in favor of LangGraph. No reason to adopt a legacy API.
- **Smolagents / custom hand-rolled** — would work but throws away battle-tested production patterns and inverts the build/buy trade-off.

## Consequences

**Gain:**
- Native `interrupt()` for analyst HITL approval — no DIY plumbing.
- `PostgresSaver` checkpointer = resumable investigations after crash, time-travel replay for debugging.
- Multi-agent headroom for month 6+ specialist agents (supervisor / swarm patterns).
- LangSmith tracing is first-class for graph execution (time-travel, replay).
- Large production footprint in SOC/security space — prior-art to learn from.
- MCP integration via `langchain-mcp-adapters`.

**Accept:**
- `langchain-core` in dep tree (heavier than Pydantic AI's stack).
- Weaker type safety than Pydantic AI (state is `TypedDict`; we wrap with Pydantic manually).
- 2-3 days learning curve (graph + state + reducers + checkpointer + interrupts).
- LangChain ecosystem API churn is real — pin dep versions aggressively.
- LangSmith is SaaS-first (self-host exists but heavier).

## Related

- ADR 0009 — JSONB HITL rules engine (uses `interrupt()`).
- ADR 0013 — LangSmith as observability backend.
- `docs/context/stack-locks.md` — agent framework lock.
