# 0001: Single Docker Compose topology for MVP

Date: 2026-04-15
Status: Accepted

## Context

Sentient Layer needs a deployment model that:
- Costs zero cloud spend during 12-month bootstrap runway.
- Runs on founder's own on-prem Splunk server (design partner #0 = founder himself).
- Supports the eventual sovereignty story (self-hosted data plane at customer DC).
- Does not burn weeks on infra before product-market fit.

Two viable models surfaced:
- **All-in-one single-stack local**: everything in one `docker-compose.yml` on one machine.
- **Split control plane (SaaS) + data plane (customer DC)**: correct final topology for multi-tenant SaaS but requires tunnel/broker plumbing before any end-user value.

## Decision

**Single `docker-compose.yml` on the founder's Splunk server for MVP.**

All services (web, api, orchestrator, worker, mcp-splunk, postgres, redis, minio, traefik) in one compose file. One machine. Founder is both vendor and design partner #0.

Split topology deferred until first external customer onboards (wk 10+).

## Alternatives considered

- **Split control/data plane from wk 1** — correct final architecture but adds 3-4 weeks of tunnel + auth + broker plumbing before shipping any user-visible value. YAGNI for a solo bootstrap MVP.
- **Cloud-hosted SaaS only (AWS Sydney)** — lowest founder ops burden, but burns A$200-500/mo infra during bootstrap and weakens the sovereignty story.
- **Kubernetes / Terraform / ECS from day 1** — kills solo-bootstrap velocity. Deferred until first paying customer requires it.

## Consequences

**Gain:**
- Zero cloud spend during runway.
- Fast iteration loop (everything local, `docker compose up`).
- Same artifacts later migrate to customer-hosted self-host OR AWS ECS via compose-to-task-def tooling.
- Single-command onboarding for design partners.

**Accept:**
- Must re-plan deployment when first external customer lands (wk 10+). Expected, plan accommodates it.
- Not production-hardened for multi-node / HA scenarios. Fine for MVP; revisit post-MVP.

## Related

- `docs/context/stack-locks.md` — current state of deployment config.
- `docs/PLAN.md` — strategic bootstrap constraints.
