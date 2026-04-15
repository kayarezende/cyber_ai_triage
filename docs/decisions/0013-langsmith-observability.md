# 0013: LangSmith + structlog for observability

Date: 2026-04-15
Status: Accepted

## Context

Two observability needs:
1. **Agent execution tracing** — what did the agent do? Which tools did it call? What did each LLM turn look like? Where did it spend tokens? Required for debugging failed investigations + prompt tuning.
2. **Application logs** — standard request/worker/errors/lifecycle logs.

Options for agent tracing:
- **LangSmith** — LangChain team's SaaS platform, graph-native, replay-capable, best in class for LangGraph traces.
- **Logfire** — Pydantic team's OTEL-based platform, cleaner for typed Python, framework-agnostic.
- **OTEL → Jaeger/Tempo/Grafana** — self-hosted, vendor-neutral, more infra to run.
- **stdout structured logs only** — cheapest, weakest debugging UX.

Options for app logs:
- `structlog` → stdout JSON (12-factor, Docker-native).
- Loki / Grafana / Prometheus stack.

## Decision

**Agent tracing: LangSmith.** First-class LangGraph integration, replay/time-travel across graph executions, no self-hosted infra to run.

**App logs: `structlog` → stdout JSON.** Docker captures to container logs. `docker logs` + `jq` for local debugging in MVP.

**Platform metrics (Prometheus, Grafana, Loki): defer post-MVP.** Not needed for founder-solo MVP on one machine.

## Alternatives considered

- **Logfire** — also strong but since we chose LangGraph (ADR 0003), LangSmith's graph-native replay is a tighter fit. Logfire would be first choice if we'd gone Pydantic AI.
- **OTEL self-hosted** — more control, no SaaS data exit, but runs an extra telemetry stack the founder doesn't have time to maintain. Defer to post-MVP.
- **No agent tracing (just stdout)** — debugging a complex LangGraph failure from stdout is painful. Rejected.
- **Loki/Grafana for app logs** — good post-MVP but MVP needs are served by `docker logs`.

## Consequences

**Gain:**
- LangSmith's LangGraph tracing shows the full node execution with state transitions and replay — best-in-class DX for our exact stack.
- `structlog` JSON is machine-parseable, survives any future pivot to Loki/OTEL.
- Zero infra to run for observability in MVP.

**Accept:**
- LangSmith is SaaS (self-host exists but heavier). Agent prompts + sanitized payloads leave the environment — must scrub PII or mark traces as non-sensitive before sending. Disable tracing entirely for prod customer tenants that require it (env flag).
- LangSmith has a free tier + paid seats (~$39/seat/mo). Ongoing operational cost.
- `docker logs` is slow when log volume grows — revisit when log volume demands Loki.

## Related

- ADR 0003 — LangGraph (the thing LangSmith traces).
- `docs/context/stack-locks.md` — observability lock.
