# 0005: Python backend, Next.js frontend

Date: 2026-04-15
Status: Accepted

## Context

Solo dev. Needs to minimize cognitive load while shipping a real SOC product with:
- Agent reasoning loops (benefits from Python ML ecosystem).
- SOC analyst UI with reasoning traces, evidence chains, audit log exploration, admin configuration (benefits from React/Next.js).
- Strong type safety.
- Small test surface area.

## Decision

**Python 3.12 for all backend** — agent (LangGraph), API (FastAPI), workers, MCP server(s). Pydantic v2 for schemas. `ruff` + `black` + `mypy --strict`.

**Next.js 15 + Tailwind + TypeScript (strict) for frontend only.** App Router. Server components by default. Minimal TS surface — mostly data fetching + render.

## Alternatives considered

- **TypeScript everywhere (Next.js backend + frontend)** — uniform language but loses Python ML/SOC ecosystem (Splunk SDK, MCP Python SDK quality, STIX libraries, OCSF validators). Rejected for ecosystem fit.
- **Python everywhere (Django/Flask + HTMX for UI)** — possible but SOC analyst viewer (reasoning trace, MITRE matrix heatmap, time-travel replay, audit log explorer) wants SPA ergonomics. Rejected for UX ceiling.
- **Python backend + Svelte/Vue frontend** — lighter framework options exist but Next.js has the largest talent pool for future hires and a mature AI-app ecosystem (Vercel AI SDK, streaming primitives).

## Consequences

**Gain:**
- Backend stays in Python where the agent/MCP/data ecosystem is strongest.
- Frontend stays in Next.js where SPA UX for SOC analysts is strongest.
- Pydantic unifies schema language across backend; TypeScript types on frontend.
- Two test runners (`pytest`, Playwright) but scoped to clearly different layers.

**Accept:**
- Two languages + two package managers.
- Schema drift risk between Pydantic (backend) and TS types (frontend). Mitigate: generate TS types from Pydantic models via `datamodel-code-generator` or FastAPI's OpenAPI output.
- Developer context switching — minor for a single dev, manageable.

## Related

- ADR 0003 — LangGraph for agent framework (Python).
- `docs/context/stack-locks.md` — languages lock.
