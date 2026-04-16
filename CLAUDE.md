# Sentient Layer (working dir: cyber-ai-triage)

Sovereign AI SOC triage platform for Australian MSSPs + mid-market. SIEM-agnostic, **Splunk-first MVP**. Domain: `sentientlayer.ai`. See `docs/PLAN.md` for strategy, `tasks/todo.md` for the build plan, `docs/context/` for current state, `docs/decisions/` for ADRs.

---

## What this repo is

An AI SOC analyst that ingests SIEM notable events, investigates autonomously with Claude + MCP tools over a LangGraph state machine, and writes an OCSF Detection Finding (verdict, confidence, MITRE ATT&CK mapping, evidence chain) back to the SIEM so the human analyst sees an enriched notable inline in their existing tool.

**MVP wedge:** Splunk on-prem triage agent. Founder's own Splunk box = dev environment + design partner #0.
**Wk 10-14 / post-MVP:** Microsoft Sentinel connector (same agent core, swap MCP server).

---

## Locked decisions (don't relitigate without reason)

| Area | Decision | Defer/Change? |
|---|---|---|
| Deployment | Single `docker-compose.yml`, one host | Split control/data plane when first external customer onboards |
| SIEM MVP | Splunk on-prem | Sentinel wk 10-14 |
| Backend languages | Python (agent, API, worker, MCP) | N/A |
| Frontend | Next.js 15 + Tailwind (minimal TS surface) | N/A |
| Agent framework | **LangGraph** + `langchain-anthropic` + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`. Agent tracing via **LangSmith**. | N/A |
| LLM routing | **OpenRouter** all tiers. Per-role config (`triage`, `investigation`, `review` active MVP; `summarize`, `entity_extraction` defined-disabled). OpenRouter native fallback chain per role. MVP dev default: `google/gemini-3-flash-preview`. Prod default: Opus + Haiku. | N/A |
| HITL | LangGraph `interrupt()` + JSONB rule engine (`hitl_policies`). MVP default: 100% human approval. | Post-MVP: drag-drop rule builder |
| Company | **Sentient Layer** (domain: `sentientlayer.ai`) | N/A |
| DB | Postgres 16, soft multi-tenancy (`tenant_id` + RLS) | Hard tenancy month 6 |
| Queue | Redis | N/A |
| Object store | MinIO (S3-compatible) | Real S3 + Object Lock in prod |
| Proxy | Traefik | N/A |
| Auth | **Dev bypass only for MVP**. Entra ID SSO → wk 11 pre-demo | N/A |
| Splunk client | `splunk-sdk` (PyPI) for search + ES endpoints via low-level `service.post()`. `httpx` for HEC (different port, different auth) | N/A |
| Enrichment | Splunk-native only | VT/AbuseIPDB/GreyNoise month 4 |
| Writeback | **Dual**: `notable_update` REST (enriches original notable in ES) + HEC post to `triage_verdicts` index | N/A |
| Standards | MITRE ATT&CK (STIX cache) + **OCSF 1.3.0** | N/A |
| Billing | Customer pays founder direct; per-tenant LLM usage tracked | N/A |
| Image upgrade | Manual Docker image tag pin in compose | Auto-update month 4+ |
| Secret encryption | Fernet via env-var `TENANT_SECRET_KEY` | Vault/KMS post-MVP |
| Logging | `structlog` → stdout JSON; Docker captures | Loki/Grafana post-MVP |
| Auto-response / SOAR | Not in MVP — recommendations only, human approves via LangGraph `interrupt()` | Opt-in month 9 |

**Why these are locked:** they were the output of a multi-round planning interview. Changing them has cost. Before revisiting, read `docs/PLAN.md` and `tasks/todo.md` for the reasoning.

---

## Project layout (target — not all dirs exist yet)

```
cyber-ai-triage/
├── docker-compose.yml          # single MVP stack
├── docker-compose.override.yml # dev overrides
├── .env.example
├── docs/
│   ├── PLAN.md                 # strategic plan (positioning, GTM, risks)
│   ├── compliance-mapping.md   # E8 + APRA CPS 234 claims
│   ├── ocsf-mapping.md         # Splunk ↔ OCSF field maps
│   └── mitre-detection-rules.md
├── apps/
│   ├── orchestrator/           # Python, LangGraph agent loop
│   ├── api/                    # Python, FastAPI
│   ├── web/                    # Next.js 15 + Tailwind
│   └── worker/                 # Python, Redis queue consumer
├── mcp/
│   └── splunk/                 # MCP Splunk server (Python)
├── libs/
│   └── ocsf/                   # OCSF schema validators + mappers
├── db/
│   ├── migrations/             # Alembic
│   └── seeds/                  # MITRE STIX import + detection rules
├── evals/
│   ├── harness/                # eval runner
│   ├── datasets/               # Splunk BOTS, Atomic Red Team, honeypot
│   ├── golden-set.jsonl
│   └── rubrics/
├── tasks/
│   ├── todo.md                 # week-by-week build plan + status
│   └── lessons.md              # self-improvement notes (per global CLAUDE.md)
└── CLAUDE.md                   # this file
```

---

## Agent architecture (MVP)

Multi-role LLM pipeline via OpenRouter, configurable per-role in admin panel:

1. **Triage role (Tier 1, one-shot, no tools).** Fast classification of every incoming notable. Output: `{severity, confidence, mitre_guesses[], entities_to_investigate[]}`. Low/info severity auto-verdicts benign, skip Tier 2.
2. **Investigation role (Tier 2, LangGraph multi-turn).** `StateGraph` nodes: `plan → execute_tools → correlate → apply_detection_rules → draft_verdict → review → await_approval → writeback`. Generic MCP tools (`siem_query`, `siem_get_notable`, `siem_notable_update`, etc.) exposed via `langchain-mcp-adapters`. Postgres checkpointer persists state — container crash mid-run → resume from last checkpoint. `interrupt()` at `await_approval` node pauses the graph for analyst approval; resume on click. Prompt caching aggressive (system + incident + MITRE context).
3. **Review role (critic, baked in MVP).** Second LLM pass over draft verdict before HITL. Catches hallucinations, flags low-confidence reasoning for analyst attention.
4. **Deterministic post-pass.** `detection_rules` table evaluates MITRE technique sets for known killchains (ransomware: T1059.001 + T1071 + T1486). Can override agent severity. Keeps critical correlations rule-based, not purely LLM-judged.
5. **Dual writeback.** Final OCSF Detection Finding posted to Splunk via **(a)** `notable_update` REST to attach verdict + link on the original notable (analyst sees it in ES) **and** **(b)** HEC post to `triage_verdicts` index for our own queryable record.

**OpenRouter native fallback** per role: request includes `"models": [primary, *fallback_chain], "route": "fallback"`. If all models fail → investigation marked inconclusive + dashboard card with attempt history + `notable_update` posts "human review needed".

---

## Standards enforcement

### MITRE ATT&CK
- STIX 2.1 from `mitre/cti` seeded into `mitre_techniques` table at build time.
- Every investigation must emit `mitre_techniques[]` (array of T-codes).
- Severity floor derived from technique impact matrix.
- Detection rules key off technique sets, not free text.

### OCSF 1.3.0
- **Pin** to 1.3.0. No chasing latest.
- Splunk notable → OCSF Detection Finding (class_uid 2004) on ingest.
- Agent outputs → OCSF Detection Finding on writeback, with populated `attacks[]` + `finding_info` + custom extension fields (`verdict`, `confidence`, `evidence_url`).

---

## Quickstart (once scaffolded)

```bash
cp .env.example .env
# edit: SPLUNK_HOST, SPLUNK_TOKEN, SPLUNK_HEC_TOKEN, ANTHROPIC_API_KEY, OPENROUTER_API_KEY, TENANT_SECRET_KEY, DEV_BYPASS_AUTH=1

docker compose up -d
docker compose logs -f orchestrator
```

App at `https://app.triage.local` (Traefik TLS). API at `https://api.triage.local`.

To trigger a test investigation from Splunk:
1. Create a saved search with alert action = webhook → `https://api.triage.local/api/incidents/ingest`.
2. Drop a test notable.
3. Investigation runs; verdict POSTed back via `notable_update` + HEC.

---

## Development conventions

- **Python:** 3.12, `ruff` + `black` + `mypy --strict`. Pydantic v2 for schemas. FastAPI routers grouped by domain.
- **TypeScript:** strict mode on. Next.js App Router. No Pages Router. Server components by default.
- **Tests:** `pytest` for Python, `playwright` for e2e. Every MCP tool and OCSF mapper has unit tests. Pydantic tool-contract schemas + golden tests to catch drift.
- **Migrations:** Alembic only. No raw SQL in app code outside migrations.
- **Secrets:** `.env` for dev. Never committed. Per-tenant Splunk tokens live encrypted in Postgres (`tenants.splunk_token_encrypted`, Fernet key from env).
- **Audit log:** append-only Postgres table, INSERT-only role. Hash chain content for tamper evidence.
- **LLM usage:** every call logged to `usage` table with token counts + USD cost. No untracked inference.
- **Logging:** `structlog` → stdout JSON everywhere. Docker captures.
- **Prompt injection defense:** untrusted fields from Splunk events pass through a sanitizer before entering agent context. Agent has **tool-only access** — no shell, no filesystem, no network beyond MCP servers.

---

## What this product is NOT

- Not a SIEM. We plug into Splunk/Sentinel, not replace them.
- Not a SOAR. We output recommended actions; humans or existing SOAR execute.
- Not an auto-response system in MVP. Every containment action is analyst-approved via LangGraph `interrupt()`.
- Not a foundation model. Claude is the accelerant, not the moat.
- Not pursuing Kubernetes, Terraform, service mesh, or IRAP PROTECTED in MVP.

---

## Pointers

- Strategic plan + GTM + risks: `docs/PLAN.md`
- Current stack locks + context: `docs/context/` (product-overview, user-context, stack-locks, mvp-scope)
- Architecture Decision Records (historical reasoning): `docs/decisions/` (see README.md for index)
- Week-by-week build plan: `tasks/todo.md`
- Self-improvement notes: `tasks/lessons.md`
- Global Claude behavior: `~/.claude/CLAUDE.md`

**Reading order for a new dev / fresh Claude session:**
1. `docs/context/product-overview.md` — what Sentient Layer is.
2. `docs/context/stack-locks.md` — current state of decisions.
3. `docs/decisions/README.md` — index of ADRs for reasoning behind each lock.
4. `tasks/todo.md` — what's next to build.
