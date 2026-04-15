# Sentient Layer — MVP Build Plan

**Status:** Planning complete. Ready to build.
**Timeline:** 13 weeks solo full-time + 2 buffer weeks = 15 wks worst case.
**Deployment:** Single `docker-compose.yml` on founder's on-prem Splunk server.
**Role:** Founder = design partner #0. External design partners = wk 12+.
**Company:** Sentient Layer (`sentientlayer.ai`).

---

## Locked Decisions

For reasoning behind each, see `docs/decisions/` (ADRs). For current state, see `docs/context/stack-locks.md`.

| Area | Decision | ADR |
|---|---|---|
| **Deployment** | Single `docker-compose.yml` on founder's Splunk server. | 0001 |
| **SIEM MVP** | Splunk on-prem. Generic MCP tool names (`siem_*`). Sentinel wk 10-14 / post-MVP. | 0002 |
| **Agent framework** | LangGraph + langchain-anthropic + langchain-mcp-adapters + langgraph-checkpoint-postgres. | 0003 |
| **LLM routing** | OpenRouter all tiers. Per-role config. Native fallback chains. MVP dev default `google/gemini-3-flash-preview`. | 0004, 0010 |
| **Languages** | Python 3.12 backend (agent, API, worker, MCP). Next.js 15 + TS frontend only. | 0005 |
| **Multi-tenancy** | Soft — `tenant_id` column + Postgres RLS. Hard tenancy deferred month 6. | 0006 |
| **Standards** | OCSF 1.3.0 + MITRE ATT&CK enforced end-to-end. | 0007 |
| **Writeback** | Dual: `siem_notable_update` REST + `siem_hec_post` to `triage_verdicts` index. | 0008 |
| **HITL** | JSONB rule engine (`hitl_policies`). MVP default = 100% human approval. LangGraph `interrupt()`. | 0009 |
| **Auth** | Dev bypass MVP (`DEV_BYPASS_AUTH=1`). Entra SSO wk 11. | 0011 |
| **Secret encryption** | Fernet via env-var `TENANT_SECRET_KEY`. | 0012 |
| **Observability** | LangSmith for agent tracing. `structlog` JSON to stdout. | 0013 |
| **Webhook auth** | Shared secret `INGEST_WEBHOOK_SECRET` MVP. | 0014 |
| **Billing / LLM keys** | Cloud-hosted MVP uses founder's master OpenRouter key. Per-tenant usage tracked. | 0004 |
| **Image upgrade** | Manual Docker tag pin in compose. | — |
| **Eval set** | Splunk BOTS v3 (derive from CTF keys) + Atomic Red Team + honeypot + hand-label ambiguous. 50+ labeled. | — |
| **Testing** | pytest (unit + integration) + Playwright (e2e) + mocked MCP + VCR LLM cassettes. Full suite on CI. | — |

---

## LLM Roles (per-role config, admin-panel driven)

| Role | MVP status | MVP dev model | Production default (admin-settable) | Purpose |
|---|---|---|---|---|
| `triage` | **active** | `google/gemini-3-flash-preview` | `anthropic/claude-haiku-4-5` | Tier 1 classification (one-shot, no tools) |
| `investigation` | **active** | `google/gemini-3-flash-preview` | `anthropic/claude-opus-4-6` | Tier 2 agent loop (LangGraph + MCP tools) |
| `review` | **active** | `google/gemini-3-flash-preview` | `anthropic/claude-sonnet-4-6` | Critic on draft verdict before HITL |
| `summarize` | defined, disabled | — | `anthropic/claude-haiku-4-5` | Human-readable summary for Splunk + UI (post-MVP) |
| `entity_extraction` | defined, disabled | — | `anthropic/claude-haiku-4-5` | OCSF normalization assist (post-MVP) |

Each row has: `primary_model`, `fallback_chain[]`, `max_tokens`, `temperature`, `timeout_seconds`, `enabled`. OpenRouter native fallback handles model retry.

---

## Repo Layout

```
cyber-ai-triage/                    # will be renamed when brand solidifies
├── docker-compose.yml              # single MVP stack
├── docker-compose.override.yml     # dev hot-reload, exposed ports
├── .env.example
├── README.md                       # quickstart: docker compose up
├── CLAUDE.md                       # project-level AI instructions
├── docs/
│   ├── PLAN.md                     # strategic plan (positioning, GTM, risks)
│   ├── context/                    # current-state snapshots
│   │   ├── product-overview.md
│   │   ├── user-context.md
│   │   ├── stack-locks.md
│   │   └── mvp-scope.md
│   ├── decisions/                  # ADRs (immutable)
│   │   ├── README.md
│   │   ├── 0001-single-docker-compose-mvp-topology.md
│   │   └── …
│   ├── compliance-mapping.md       # E8 + APRA CPS 234 claims (wk 13)
│   ├── ocsf-mapping.md             # Splunk ↔ OCSF field map (wk 3)
│   ├── mitre-detection-rules.md    # rule format + examples (wk 8)
│   ├── splunk-setup.md             # prereqs, tokens, HEC (wk 0)
│   └── operations.md               # runbooks, rotation (wk 12)
├── apps/
│   ├── orchestrator/               # Python, LangGraph agent loop
│   ├── api/                        # Python, FastAPI
│   ├── web/                        # Next.js 15 + Tailwind
│   └── worker/                     # Python, Redis queue consumer
├── mcp/
│   └── splunk/                     # MCP server (generic SIEM interface backed by Splunk)
├── libs/
│   └── ocsf/                       # OCSF schema validators + mappers
├── db/
│   ├── migrations/                 # Alembic
│   └── seeds/                      # MITRE STIX + seed detection rules
├── evals/
│   ├── harness/
│   ├── datasets/                   # BOTS, Atomic, honeypot exports
│   ├── golden-set.jsonl
│   └── rubrics/
└── tasks/
    ├── todo.md                     # this file
    └── lessons.md                  # self-improvement notes
```

---

## docker-compose.yml Sketch

```yaml
services:
  traefik:
    image: traefik:v3

  web:
    build: ./apps/web

  api:
    build: ./apps/api
    depends_on: [postgres, redis]

  orchestrator:
    build: ./apps/orchestrator
    depends_on: [postgres, redis, mcp-splunk]

  worker:
    build: ./apps/worker
    depends_on: [redis, orchestrator]

  mcp-splunk:
    build: ./mcp/splunk
    environment:
      SPLUNK_HOST: ${SPLUNK_HOST}
      SPLUNK_TOKEN: ${SPLUNK_TOKEN}
      SPLUNK_HEC_TOKEN: ${SPLUNK_HEC_TOKEN}

  postgres:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]

  redis:
    image: redis:7

  minio:
    image: minio/minio

volumes:
  pgdata:
  miniodata:
```

---

## Postgres Schema (core tables)

```sql
-- Tenancy
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  splunk_host TEXT,
  splunk_token_encrypted BYTEA,          -- Fernet-encrypted
  splunk_hec_token_encrypted BYTEA,      -- Fernet-encrypted
  max_concurrent_investigations INT DEFAULT 5,
  monthly_llm_budget_usd NUMERIC(10,2),
  per_investigation_budget_usd NUMERIC(10,4),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  email TEXT,
  role TEXT CHECK (role IN ('analyst','admin')),
  entra_oid TEXT UNIQUE,                 -- nullable; populated at wk 11
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Per-role LLM config (ADR 0010)
CREATE TABLE llm_role_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  role TEXT CHECK (role IN ('triage','investigation','review','summarize','entity_extraction')),
  primary_model TEXT NOT NULL,
  fallback_chain TEXT[] DEFAULT '{}',
  max_tokens INT DEFAULT 4096,
  temperature NUMERIC(3,2) DEFAULT 0.2,
  timeout_seconds INT DEFAULT 30,
  enabled BOOLEAN DEFAULT TRUE,
  UNIQUE(tenant_id, role)
);

-- Incidents ingested from SIEM
CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  siem_source TEXT DEFAULT 'splunk',     -- 'splunk', 'sentinel', etc.
  siem_notable_id TEXT,
  received_at TIMESTAMPTZ DEFAULT NOW(),
  raw_payload_s3_key TEXT,
  ocsf_normalized JSONB,
  status TEXT CHECK (status IN ('new','triaging','investigating','awaiting_approval','done','failed','inconclusive'))
);

-- Investigation runs
CREATE TABLE investigations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID,
  incident_id UUID REFERENCES incidents(id),
  langgraph_thread_id TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  verdict TEXT CHECK (verdict IN ('true_positive','false_positive','benign','inconclusive')),
  confidence NUMERIC(3,2),
  severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
  mitre_techniques TEXT[],
  summary TEXT,
  evidence_s3_key TEXT,
  ocsf_output JSONB,
  review_notes TEXT,                     -- from review role
  human_approved_by UUID REFERENCES users(id),
  human_approved_at TIMESTAMPTZ,
  inconclusive_reason TEXT               -- nullable; populated when fallback chain exhausted
);

-- Append-only audit log
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  investigation_id UUID,
  actor TEXT,                            -- user email | 'system' | 'agent:role'
  action TEXT,                           -- llm_call | tool_call | user_approve | ingest | role_config_change
  details JSONB,
  content_hash TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
-- REVOKE UPDATE, DELETE on audit_log; INSERT only.

-- LLM usage for chargeback (logs each attempt, including failures)
CREATE TABLE usage (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  investigation_id UUID,
  role TEXT,                             -- which role made the call
  attempt_num INT,                       -- 1 = primary, 2+ = fallback
  model_requested TEXT,                  -- what we asked for
  model_used TEXT,                       -- what OpenRouter served
  status TEXT CHECK (status IN ('success','timeout','5xx','validation_fail','rate_limited')),
  input_tokens INT,
  output_tokens INT,
  cached_tokens INT,
  cost_usd NUMERIC(10,6),
  openrouter_generation_id TEXT,
  latency_ms INT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- MITRE ATT&CK local cache
CREATE TABLE mitre_techniques (
  technique_id TEXT PRIMARY KEY,
  tactic_ids TEXT[],
  name TEXT,
  description TEXT,
  platforms TEXT[],
  data_sources TEXT[],
  detection TEXT,
  raw JSONB
);

-- Deterministic detection rules
CREATE TABLE detection_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID,                        -- NULL = global
  name TEXT,
  description TEXT,
  required_techniques TEXT[],
  any_techniques TEXT[],
  severity_override TEXT,
  enabled BOOLEAN DEFAULT TRUE
);

-- HITL rule policies (ADR 0009)
CREATE TABLE hitl_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  name TEXT,
  rule_expression JSONB,                 -- {"op":"always_true"} default
  priority INT DEFAULT 100,              -- lower = first match wins
  enabled BOOLEAN DEFAULT TRUE
);

-- LangGraph checkpointer tables (created by PostgresSaver.setup())

-- RLS (repeat for all tenant-scoped tables)
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON incidents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

---

## MCP Server — Generic SIEM Tool Surface

```python
# mcp/splunk/server.py (backed by Splunk; future mcp/sentinel/ implements same contract)
tools = [
    "siem_query",              # ad-hoc SPL/KQL/etc, structured results
    "siem_get_notable",        # notable by ID + enrichment
    "siem_get_entity_history", # recent events for host/user/IP/file
    "siem_process_tree",       # parent/child for PID
    "siem_lookup_ioc",         # query threat intel lookups
    "siem_notable_update",     # attach verdict + link to original notable (ES notable_update REST)
    "siem_hec_post",           # post OCSF Detection Finding to triage_verdicts index (HEC)
]
```

- Auth: Splunk service account token per tenant (`splunk-sdk` Service), HEC token per tenant (httpx header).
- Pydantic tool-contract schemas + golden tests to catch drift.
- Every tool call logged to `audit_log` with args + sha256 of result payload.
- Splunk client: `splunk-sdk-python` for search jobs + ES endpoints via `service.post()`. `httpx` for HEC.

---

## Agent Architecture (graph)

```
[incident] → triage (role=triage)
   ├── low|info → auto-verdict benign → END (audit logged)
   └── ≥medium → enqueue investigation

[investigation StateGraph]
   plan → execute_tools → correlate → apply_detection_rules
   → draft_verdict → review (role=review) → await_approval (interrupt)
   → writeback → END

PostgresSaver checkpointer snapshots state at every node.
Crash mid-run: resume from last checkpoint via thread_id.
Time-travel: replay any prior checkpoint state in UI for debugging.
```

### Evidence manifest

Per investigation, write to MinIO:
```json
{
  "investigation_id": "...",
  "tenant_id": "...",
  "incident": { "ocsf": {...} },
  "triage_result": { ... },
  "agent_turns": [ ... ],
  "tool_calls": [
    {"tool": "siem_query", "args": {...}, "result_hash": "sha256:...", "result_s3_key": "..."}
  ],
  "draft_verdict": { ... },
  "review_notes": "...",
  "mitre_techniques": ["T1059.001", "T1071"],
  "rule_matches": [{"rule_id": "...", "name": "ransomware_killchain"}],
  "final_output": { "ocsf": {...} },
  "token_usage": {"input": ..., "output": ..., "cached": ..., "cost_usd": ...},
  "attempts": [
    {"role": "investigation", "model": "gemini-3-flash-preview", "status": "success"}
  ]
}
```

---

## Seed Detection Rules (wk 8)

10 global rules pre-populated:

| Name | Required techniques | Severity override |
|---|---|---|
| ransomware_killchain | T1059.001, T1071, T1486 | critical |
| credential_theft | T1003, T1078 | high |
| bec_pattern | T1566.002, T1078.004 | high |
| lateral_movement | T1021, T1078 | high |
| exfil_over_c2 | T1041, T1071 | high |
| persistence_scheduled_task | T1053.005 | medium |
| privesc_uac_bypass | T1548.002 | high |
| c2_dns_tunneling | T1071.004 | medium |
| data_destruction | T1485 | critical |
| brute_force_burst | T1110 | medium |

---

## Eval Harness

**Dataset sources:**
- **Splunk BOTS v3** — ingest into Splunk, derive labels from CTF answer keys (~half the set).
- **Atomic Red Team** — run in lab VM, logs to Splunk, labels are the technique ID you ran.
- **Honeypot VPS** — ongoing logs, labels are "background internet noise" / "brute force" by construction.
- **Hand-label** only ambiguous cases.

**Label schema (`evals/golden-set.jsonl`):**
```json
{
  "id": "bots-v3-001",
  "source": "bots_v3",
  "siem_notable": { ... raw ... },
  "truth": {
    "verdict": "true_positive",
    "severity": "high",
    "mitre_techniques": ["T1059.001","T1071.001"],
    "rationale": "..."
  }
}
```

**Scoring:** verdict agreement (4-class exact), MITRE F1, severity ±1, latency p50<5min/p95<15min, cost/incident budget.
**Ship gate:** ≥85% verdict agreement, ≥0.70 MITRE F1.

---

## Week-by-Week Milestones

**Wk 0 — Prep**
- [ ] `docs/splunk-setup.md`: Splunk version, ES app version, HEC token creation, service account setup.
- [ ] Decide OCSF validator library (`py-ocsf-models` vs hand-rolled Pydantic).
- [ ] Provision Anthropic + OpenRouter + LangSmith accounts.

**Wk 1 — Scaffolding + data + observability**
- [ ] Repo layout + `.gitignore`, `README.md` stub.
- [ ] `docker-compose.yml` with all service stubs building + starting.
- [ ] Postgres + Alembic + initial migration (all tables above).
- [ ] `langgraph-checkpoint-postgres` `setup()` — checkpointer tables created.
- [ ] Seed MITRE STIX → `mitre_techniques` table.
- [ ] **Load Splunk BOTS v3 into local Splunk.**
- [ ] `structlog` → stdout JSON wired in all services.
- [ ] Dev bypass auth flag (`DEV_BYPASS_AUTH=1`) in FastAPI + Next.js middleware.
- [ ] Fernet key generation + `.env.example` documented.
- [ ] LangSmith project + API key wired.
- [ ] `docker compose up` brings up empty-but-healthy stack.

**Wk 2 — MCP SIEM server v1 + framework validation**
- [ ] Python MCP server (`mcp` official SDK) exposing `siem_query`, `siem_get_notable` backed by Splunk.
- [ ] Splunk client: `splunk-sdk-python` Service for search jobs + auth/session.
- [ ] Pydantic tool-contract schemas + golden tests.
- [ ] Unit tests against local Splunk (BOTS data loaded wk 1).
- [ ] **Verify: LangGraph + ChatOpenAI-pointed-at-OpenRouter + `langchain-mcp-adapters` + `PostgresSaver` all integrate.** Minimal graph with one tool call + checkpoint round-trip, visible in LangSmith.
- [ ] **Verify: OpenRouter structured output + tool_use passthrough** with Gemini 3 Flash.

**Wk 3 — OCSF normalization layer**
- [ ] Splunk notable → OCSF 1.3.0 Detection Finding mapper.
- [ ] Validator per wk 0 decision.
- [ ] Store raw + normalized in `incidents`.
- [ ] Unit tests covering 10+ Splunk notable variants from BOTS.

**Wk 4 — Ingest path end-to-end**
- [ ] Splunk saved search + alert action → webhook to `/api/incidents/ingest` (with `X-Webhook-Secret` check).
- [ ] Job enqueue on Redis; worker picks up.
- [ ] Worker invokes orchestrator (stub verdict for now).
- [ ] Smoke: drop notable → investigation row appears with stub verdict.

**Wk 5 — Per-role LLM config + Triage**
- [ ] Seed `llm_role_config` with 5 rows per tenant (3 enabled, 2 disabled).
- [ ] OpenRouter client wrapper: takes role, looks up config, builds request with `"models": [primary, *fallback]`.
- [ ] Usage tracker logs every attempt (success/failure) with latency + cost.
- [ ] Tier 1 classification prompt with OCSF input.
- [ ] Pydantic-validated output; 1 retry on schema fail within attempt.
- [ ] Low/info verdicts auto-close without Tier 2.

**Wk 6 — Tier 2 LangGraph skeleton + parallel labeling begins**
- [ ] StateGraph skeleton: `plan → execute_tools → correlate → draft_verdict` (no HITL/review yet).
- [ ] MCP tools wired via `langchain-mcp-adapters`.
- [ ] System prompt: MITRE context, OCSF output contract, investigative methodology.
- [ ] `PostgresSaver` checkpointer wired. Crash-resume smoke test.
- [ ] Runs visible in LangSmith with full trace + replay.
- [ ] **Start labeling golden set (~2 hrs this week, target ~5 incidents).**

**Wk 7 — Tier 2 completeness + Review role + prompt caching**
- [ ] Prompt caching (`cache_control` on system + incident + MITRE blocks). Measure cache hit rate; diagnose if <50%.
- [ ] Evidence manifest format implemented; `evidence.json` to MinIO per investigation.
- [ ] Per-investigation token/cost caps (abort to inconclusive if exceeded).
- [ ] **`review` role wired.** LangGraph node `review` between `draft_verdict` and `await_approval`. Second LLM pass critiques draft verdict; flags low confidence / hallucination indicators.
- [ ] **Continue labeling (~2-3 hrs, target ~10 more incidents).**

**Wk 8 — Detection rules + HITL + dual writeback**
- [ ] `apply_detection_rules` graph node; seed 10 rules.
- [ ] `hitl_policies` evaluator (~50 line JSONB tree walker). Default policy `{"op": "always_true"}`.
- [ ] `await_approval` node using LangGraph `interrupt()`. State persists in checkpointer; resume on analyst click.
- [ ] `siem_notable_update` MCP tool — `service.post('notable_update', ...)` via SDK low-level.
- [ ] `siem_hec_post` MCP tool — `httpx` POST to `/services/collector/event` → `triage_verdicts` index.
- [ ] Verify both in Splunk: original notable gets comment + new event in triage_verdicts.
- [ ] **Continue labeling (~2-3 hrs, target ~10 more incidents).**

**Wk 9 — Web UI core (dev-bypass auth)**
- [ ] Next.js 15 app with dev-bypass middleware (no Entra yet).
- [ ] Investigation detail page: verdict, reasoning trace (from evidence manifest), evidence chain, MITRE matrix heatmap, review notes.
- [ ] **Approval UI**: button that resumes a LangGraph thread from `interrupt()`.
- [ ] Audit log explorer: filterable timeline per investigation + per tenant.
- [ ] Time-travel replay: LangGraph checkpointer exposed for stepping through prior investigation states.
- [ ] **Continue labeling (~2 hrs, target ~10 more incidents).**

**Wk 10 — Admin panel + eval harness**
- [ ] Admin panel pages:
  - LLM role config (table of 5 roles, edit primary + fallback + caps + enable toggle).
  - HITL policies (JSON textbox for `rule_expression` + enable toggle).
  - Concurrency limit + budget caps (per-investigation + monthly).
  - Splunk connection config (host, service account token, HEC token).
  - Users + roles.
  - Usage dashboard (tokens + cost + attempts by role by month).
- [ ] Eval harness: `python evals/run_eval.py` → scored HTML report.
- [ ] Atomic Red Team runs on lab VM → logs to Splunk.
- [ ] Honeypot log pipeline into Splunk.
- [ ] Finish 50-incident golden set (~35 should be labeled from wk 6-9).
- [ ] Baseline agent against golden set.

**Wk 11 — Quality iteration + Entra SSO**
- [ ] Triage eval failures → categorize (prompt / tool / schema / ambiguous label).
- [ ] Prompt + rule tuning. Target ≥85% verdict, ≥0.70 MITRE F1.
- [ ] **Entra ID SSO**: FastAPI OIDC + Next.js middleware. Dev bypass remains behind env flag.

**Wk 12 — Hardening + demo**
- [ ] End-to-end smoke tests (pytest + Playwright). Full test suite green.
- [ ] Security review: auth flow, secrets management, RLS coverage, audit log integrity, prompt-injection sanitizer, `DEV_BYPASS_AUTH` kill checklist.
- [ ] `README.md` full quickstart.
- [ ] `docs/operations.md` runbook (rotation, backups, incident response).
- [ ] Demo video (5 min).
- [ ] Self-host on VPS as internal design partner #0.
- [ ] Begin external design partner outreach.

**Wk 13 — Buffer / slippage catchup**

**Wk 14-15 — Buffer / docs completion**
- [ ] `docs/compliance-mapping.md` (E8 ML2 + APRA CPS 234).
- [ ] `docs/ocsf-mapping.md` polish.
- [ ] `docs/mitre-detection-rules.md` polish.

---

## Risks + Mitigations

| Risk | Mitigation |
|---|---|
| OpenRouter tool_use/structured output inconsistency for Gemini / Claude | Verify wk 2; fall back to JSON mode + Pydantic retry; measure per-role per-model. |
| OpenRouter `cache_control` passthrough inconsistent | Measure cache hit rate wk 7. If <50%, fallback to provider-direct for investigation role only. |
| `langchain-mcp-adapters` rough edges | Verify wk 2. Alt: manual MCP client integration. |
| `PostgresSaver` + multi-tenant concurrency | Thread IDs include tenant_id; RLS applies. Verify wk 2. |
| Splunk BOTS v3 dated (2020) | Supplement with Atomic Red Team + honeypot wk 10. |
| OCSF 1.x schema drift | Pin to 1.3.0. Don't chase bleeding edge. |
| Solo burnout at 13-15 wk FT | 1 protected day/wk off. Buffer weeks 13-15. |
| Prompt injection from Splunk data | Sanitize user-controlled fields; tool-only agent access. |
| Audit log tampering | Postgres INSERT-only role; content hash chain. |
| Review role catches too many / too few | Tune review prompt wk 11 iteration. Admin can disable review role if noisy. |

---

## Review Section (fill in after each week)

### Wk 0 Review
_Pending._

### Wk 1 Review
_Pending._

_(etc.)_
