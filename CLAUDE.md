# Sentient Layer (working dir: cyber-ai-triage)

Australian-built AI SOC triage platform for AU MSSPs + mid-market. SIEM-agnostic, **Splunk-first MVP**. Domain: `sentientlayer.ai`. **MVP is not sovereign** (OpenRouter US + LangSmith SaaS); sovereign-mode tier (BYO Bedrock Sydney / Azure AU East routing, LangSmith off, BYO LLM keys) ships post-MVP — DB surface present from MVP. See `docs/PLAN.md` for strategy, `tasks/todo.md` for the build plan, `docs/context/` for current state, `docs/decisions/` for ADRs.

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
| Agent framework | **LangGraph** + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`. Agent tracing via **LangSmith** (per-tenant `langsmith_enabled` toggle). LLM calls via custom `LLMRouter` wrapper, not `langchain-anthropic`. | N/A |
| LLM routing | **OpenRouter** all tiers. Per-role config (`triage`, `investigation`, `review` active MVP; `summarize`, `entity_extraction` defined-disabled). **App-side fallback loop** (per-attempt audit ledger). See ADR-0015. MVP dev default: `google/gemini-3-flash-preview`. Prod defaults: Opus 4.7 (investigation) + Sonnet 4.6 (review) + Haiku 4.5 (triage), all admin-overridable. | N/A |
| Splunk product tier | Splunk Enterprise (base). **Splunk ES required for `dual` writeback**; degraded `hec_only` mode (HEC post only, `notable_update` no-op) for plain Splunk. Per-tenant `writeback_mode`. See ADR-0018. | N/A |
| Sovereignty | **MVP not sovereign** (OpenRouter US + LangSmith SaaS). Hybrid surface in `tenants` table (BYO LLM keys + region constraint + langsmith toggle columns). Sovereign-mode tier ships post-MVP. See ADR-0016. | Post-MVP paid tier |
| HITL | LangGraph `interrupt()` + JSONB rule engine (`hitl_policies`). MVP default: 100% human approval. | Post-MVP: drag-drop rule builder |
| Company | **Sentient Layer** (domain: `sentientlayer.ai`) | N/A |
| DB | Postgres 16, soft multi-tenancy (`tenant_id` + RLS) | Hard tenancy month 6 |
| Queue | Redis | N/A |
| Object store | MinIO (S3-compatible) | Real S3 + Object Lock in prod |
| Proxy | Traefik | N/A |
| Auth | **Dev bypass only for MVP**. Entra ID SSO → wk 11 pre-demo | N/A |
| Splunk client | `splunk-sdk` (PyPI) for search + ES endpoints via low-level `service.post()`. `httpx` for HEC (different port, different auth) | N/A |
| Enrichment | Splunk-native only | VT/AbuseIPDB/GreyNoise month 4 |
| Writeback | Per-tenant `writeback_mode`. `dual` (ES tenants): `notable_update` REST + HEC. `hec_only` (base Splunk): HEC only. Default `hec_only` (conservative). | N/A |
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

**App-side fallback loop** per role (`LLMRouter` wrapper at `apps/orchestrator/src/llm/router.py`). Tries primary → catches `httpx.TimeoutException` / `httpx.HTTPStatusError` → logs per-attempt row in `usage` (`attempt_num`, `status`, `latency_ms`, `model_requested`) → tries next model in `fallback_chain`. If all models fail → raises `FallbackChainExhausted` → investigation marked `inconclusive`, `inconclusive_reason` populated, dashboard card with attempt history, writeback posts "human review needed". Per-attempt audit ledger required for compliance posture (see ADR-0015).

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
# edit: SPLUNK_HOST, SPLUNK_TOKEN, SPLUNK_HEC_TOKEN, OPENROUTER_API_KEY, TENANT_SECRET_KEY, LANGSMITH_API_KEY, INGEST_WEBHOOK_SECRET, DEV_BYPASS_AUTH=1

docker compose up -d
docker compose logs -f orchestrator
```

App at `https://app.triage.local` (Traefik TLS). API at `https://api.triage.local`.

To trigger a test investigation from Splunk:
1. Create a saved search with alert action = webhook → `https://api.triage.local/api/incidents/ingest`.
2. Drop a test notable.
3. Investigation runs; verdict POSTed back via writeback (HEC always, plus `notable_update` if tenant `writeback_mode='dual'` and Splunk ES is installed).

---

## Development conventions

- **Python:** 3.12, `ruff` + `black` + `mypy --strict`. Pydantic v2 for schemas. FastAPI routers grouped by domain.
- **TypeScript:** strict mode on. Next.js App Router. No Pages Router. Server components by default.
- **Tests:** `pytest` for Python, `playwright` for e2e. Every MCP tool and OCSF mapper has unit tests. Pydantic tool-contract schemas + golden tests to catch drift.
- **Migrations:** Alembic only. No raw SQL in app code outside migrations.
- **Secrets:** `.env` for dev. Never committed. Per-tenant Splunk tokens live encrypted in Postgres (`tenants.splunk_token_encrypted`, Fernet key from env).
- **Audit log:** hash-chained append-only Postgres table. `previous_hash` + `hash_scope` columns. Compute trigger on INSERT; UPDATE/DELETE blocked by triggers. `audit_writer` DB role with INSERT/SELECT only. See ADR-0017.
- **LLM usage:** every attempt (success + failure) logged to `usage` table with `attempt_num`, `model_requested`, `model_used`, status, token counts, USD cost, latency. App-side fallback loop owns the logging — see ADR-0015. No untracked inference.
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
