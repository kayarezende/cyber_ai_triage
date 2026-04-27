# Architecture Decision Records (ADRs)

ADRs are short, dated, immutable documents recording the **why** behind significant architecture decisions. One file per decision.

## Why ADRs?

- **Future you / future devs / future AI assistants** read this to understand why the code looks the way it does without needing to ask the original author.
- Decisions rot; memory rots faster. Writing down the *context* + *alternatives* + *consequences* at decision time is cheap insurance.
- Moves with the repo. Survives dev turnover, machine swaps, acquisitions.

## When to write a new ADR

Write one when you make a decision that:
- Closes off other paths (e.g., "we use LangGraph, not Pydantic AI").
- Has real trade-offs worth remembering.
- Shapes how multiple parts of the system fit together.

Don't write an ADR for every PR. Write one for every architectural fork.

## Lifecycle

- **Proposed** — drafted, under discussion.
- **Accepted** — decision made and in force.
- **Superseded** — a later ADR replaced it (link forward via "Superseded by: ADR-0XXX").

**Never edit an accepted or superseded ADR.** Write a new ADR that supersedes it. ADRs are a historical record, not a living wiki. For current state, see `docs/context/stack-locks.md`.

## File naming

`NNNN-kebab-case-title.md` where `NNNN` is a monotonically increasing 4-digit number.

## Template

```markdown
# NNNN: Short Title

Date: YYYY-MM-DD
Status: Accepted | Proposed | Superseded by ADR-NNNN

## Context
What problem did we face? What constraints were in play?

## Decision
What did we pick?

## Alternatives considered
What else did we look at? Why did we reject each?

## Consequences
What costs do we accept? What do we gain? What becomes harder?

## Related
- Link to other ADRs, code, external docs.
```

## Index

| # | Title | Status |
|---|---|---|
| 0001 | [Single Docker Compose topology for MVP](0001-single-docker-compose-mvp-topology.md) | Accepted |
| 0002 | [Splunk-first, SIEM-agnostic MCP abstraction](0002-splunk-first-siem-agnostic-mcp.md) | Accepted |
| 0003 | [LangGraph as the agent framework](0003-langgraph-agent-framework.md) | Accepted |
| 0004 | [OpenRouter as unified LLM routing](0004-openrouter-unified-llm-routing.md) | Accepted (fallback §4 superseded by 0015) |
| 0005 | [Python backend, Next.js frontend](0005-python-backend-nextjs-frontend.md) | Accepted |
| 0006 | [Soft multi-tenancy via Postgres RLS](0006-soft-multi-tenancy-rls.md) | Accepted |
| 0007 | [OCSF 1.3.0 + MITRE ATT&CK as enforced standards](0007-ocsf-and-mitre-standards.md) | Accepted (validator §refined by 0020) |
| 0008 | [Dual Splunk writeback (HEC + notable_update)](0008-dual-splunk-writeback.md) | Accepted (refined by 0018) |
| 0009 | [JSONB-based HITL rules engine](0009-jsonb-hitl-rules-engine.md) | Accepted |
| 0010 | [Per-role LLM configuration](0010-per-role-llm-configuration.md) | Accepted (fallback §3 superseded by 0015) |
| 0011 | [Dev-bypass auth for MVP, Entra SSO in wk 11](0011-dev-bypass-auth-mvp-entra-wk11.md) | Accepted |
| 0012 | [Fernet-based secret encryption](0012-fernet-secret-encryption.md) | Accepted |
| 0013 | [LangSmith + structlog for observability](0013-langsmith-observability.md) | Accepted |
| 0014 | [Shared-secret webhook auth for MVP](0014-shared-secret-webhook-auth.md) | Accepted (carrier §refined by 0021) |
| 0015 | [App-side LLM fallback loop](0015-app-side-llm-fallback.md) | Accepted (supersedes 0004 §4) |
| 0016 | [Sovereignty hybrid surface — drop MVP claim, prepare DB](0016-sovereignty-mode-hybrid.md) | Accepted |
| 0017 | [Hash-chained audit log + DB role split](0017-audit-hash-chain.md) | Accepted |
| 0018 | [Splunk writeback mode (`dual` vs `hec_only`)](0018-splunk-writeback-mode.md) | Accepted (refines 0008) |
| 0019 | [MCP transport: `streamable_http`](0019-mcp-transport-streamable-http.md) | Accepted |
| 0020 | [OCSF 1.3.0 validator: hand-rolled Pydantic v2](0020-ocsf-validator-handrolled-pydantic.md) | Accepted (refines 0007) |
| 0021 | [Webhook secret carrier — body field](0021-webhook-secret-body-field.md) | Accepted (refines 0014) |
