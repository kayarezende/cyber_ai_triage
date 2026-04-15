# Founder Context — Kaya

## Background

- Cybersecurity operator / SOC analyst + AI/ML engineer.
- Based in Australia, targeting AU market first, international expansion later.
- Bootstrap founder (self-funded, <12 month runway). Solo by default.

## Working style

- Direct, terse feedback. Prefers fragments over prose when discussing technical choices.
- Values realistic/skeptical market analysis over hype.
- Plans thoroughly before building — went through multi-round planning interview before first commit.
- Prefers Docker Compose / containerized local-first development over cloud infra for MVP stage.

## Technical edge

- Can build the AI agent side himself (LangGraph + MCP + Claude) — AI/ML engineer background.
- SOC domain knowledge gives quality-eval advantage over generalist competitors.
- Has own on-prem Splunk instance = built-in dev + demo environment + design partner #0 for the MVP phase.

## Communication preferences

- Short direct responses during planning. Avoid pleasantries.
- When proposing architecture, give alternatives + my recommendation + trade-offs, not just one option.
- Explicitly correct wrong premises (e.g. "scale argument is wrong but decision is correct") — don't just agree sycophantically.
- Prefers explicit lock/confirm cycles over implicit assumptions.
- Wants reasoning documented for future reference (hence ADRs).

## Values for the product

- Security ("our app needs to be secure so do the secure option").
- Configurability — admin panel controls for HITL policies, LLM routing per role, budget caps, concurrency.
- Observability — audit log everything, keep all logs forever in MVP.
- Future-proofing — generic MCP abstractions now so adding SIEMs later is cheap.

## Pointers

- Full strategic context: `docs/PLAN.md`
- MVP scope: `docs/context/mvp-scope.md`
