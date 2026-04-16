# Stack Locks — Current State

**Last updated:** 2026-04-15

Snapshot of current architectural commitments. Immutable reasoning for each is in `docs/decisions/` (ADRs). Update this file when a lock changes; do not rewrite ADRs.

---

## Deployment + topology

| Area | Lock |
|---|---|
| MVP deployment | Single `docker-compose.yml` on founder's on-prem Splunk server. |
| Control/data plane split | Deferred until first external customer onboards (wk 10+). |
| Kubernetes / Terraform / mesh | Not in MVP. Revisit with first paying customer. |

→ See ADR 0001

## SIEM + integrations

| Area | Lock |
|---|---|
| SIEM MVP | Splunk on-prem (founder's own). |
| Sentinel connector | Wk 10-14 or post-MVP. |
| Future SIEMs | CrowdStrike Falcon, Defender XDR — month 4-6+. |
| MCP tool names | Generic (`siem_query`, `siem_get_notable`) so agent prompts are SIEM-agnostic. |
| Splunk client | `splunk-sdk` (PyPI) for search + ES endpoints via low-level `service.post()`. `httpx` for HEC (different port, different auth). |
| Writeback | Dual: `notable_update` REST (enriches original notable in ES) + HEC post to `triage_verdicts` index. |
| Enrichment | Splunk-native only for MVP. VT/AbuseIPDB/GreyNoise deferred month 4. |

→ See ADR 0002, 0008

## Agent framework

| Area | Lock |
|---|---|
| Framework | **LangGraph** + `langchain-anthropic` (or `langchain-openai` for OpenRouter) + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`. |
| Why | Native `interrupt()` HITL + Postgres checkpointer + multi-agent runway. |
| Tracing | LangSmith (SaaS, graph-native). |
| MCP server library | Official `mcp` Python SDK. |

→ See ADR 0003, 0013

## LLM routing

| Area | Lock |
|---|---|
| Provider | **OpenRouter** for all tiers + all roles in MVP. |
| Per-role config | Admin panel configures `primary_model` + `fallback_chain[]` + caps per role. |
| Roles active MVP | `triage`, `investigation`, `review`. |
| Roles defined but disabled MVP | `summarize`, `entity_extraction`. |
| Fallback mechanism | OpenRouter native (`"route": "fallback"`, list of models in request). No fallback logic in our code. |
| Prompt caching | Aggressive — system + incident payload + MITRE context. 5-6x cost cut per investigation. |
| MVP dev default model | `google/gemini-3-flash-preview` (cheap, fast, good-enough for testing). |
| Production default | `anthropic/claude-opus-4-6` for investigation; `anthropic/claude-haiku-4-5` for triage. |

→ See ADR 0004, 0010

## Languages + frameworks

| Area | Lock |
|---|---|
| Backend | **Python 3.12** for agent, API, worker, MCP. |
| Code quality | `ruff`, `black`, `mypy --strict`, Pydantic v2. |
| Frontend | **Next.js 15** + Tailwind + TypeScript (strict). App Router, server components by default. |
| API framework | FastAPI. |

→ See ADR 0005

## Data

| Area | Lock |
|---|---|
| DB | Postgres 16. |
| Queue | Redis. |
| Object store | MinIO (S3-compatible MVP; swap to S3 + Object Lock in prod). |
| Proxy | Traefik. |
| Multi-tenancy | **Soft** — `tenant_id` column + Postgres RLS. Hard tenancy deferred month 6. |
| Retention | Unlimited in MVP (keep all logs forever). Configurable per tenant post-MVP. |

→ See ADR 0006

## Standards

| Area | Lock |
|---|---|
| Threat model | MITRE ATT&CK (STIX 2.1 cache seeded into Postgres at build). |
| Event schema | OCSF 1.3.0 (Splunk → OCSF in; OCSF Detection Finding out). |
| Validator | `py-ocsf-models` pinned if supports 1.3.0; else hand-rolled Pydantic. |

→ See ADR 0007

## Auth + secrets

| Area | Lock |
|---|---|
| Auth MVP | Dev bypass only (env flag + simple email). |
| Auth post-MVP | Entra ID SSO — implemented wk 11 pre-demo. |
| Secret encryption | Fernet with env-var key `TENANT_SECRET_KEY`. |
| Rotation | Manual + documented in runbook MVP. Admin API post-MVP. |
| Webhook auth | Shared secret env var `INGEST_WEBHOOK_SECRET` MVP. HMAC post-MVP. |

→ See ADR 0011, 0012, 0014

## Observability

| Area | Lock |
|---|---|
| App logs | `structlog` → stdout JSON. Docker captures. |
| Agent tracing | LangSmith (SaaS). |
| Platform metrics | None in MVP. Loki/Grafana/Prometheus post-MVP. |

→ See ADR 0013

## HITL (human-in-loop)

| Area | Lock |
|---|---|
| Mechanism | LangGraph `interrupt()` node in StateGraph. |
| Policy | JSONB `rule_expression` tree stored per tenant in `hitl_policies`. |
| MVP default | `{"op": "always_true"}` — 100% human approval. |
| Post-MVP | Admin UI rule builder; confidence + severity + AND/OR logic. |

→ See ADR 0009

## Billing / LLM key ownership

| Area | Lock |
|---|---|
| Cloud-hosted MVP | Founder's master OpenRouter key. Per-tenant usage tracked for chargeback. |
| Future on-prem | Customer brings their own LLM API keys (different deployment model). |
| Budget caps | Per-investigation + per-tenant-monthly, both admin-configurable. |

→ See ADR 0004, 0010

## Upgrade model

| Area | Lock |
|---|---|
| MVP | Manual Docker image tag pin in compose. Customer-controlled. |
| Post-MVP | Admin UI approved minor auto-updates; month 4+. |

## Testing

| Area | Lock |
|---|---|
| Unit | `pytest` — every MCP tool, OCSF mapper, detection rule has unit tests. |
| Integration | Real Splunk (BOTS data) locally (not CI). Mocked MCP + VCR LLM cassettes for CI. |
| E2E | Playwright for web flows. |
| Contract | Pydantic tool-contract schemas + golden tests to catch MCP drift. |
