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
| **Agent framework** | LangGraph + langchain-mcp-adapters + langgraph-checkpoint-postgres. LLM via custom `LLMRouter` (not langchain-anthropic) so app-side fallback owns logging. | 0003, 0015 |
| **LLM routing** | OpenRouter all tiers. Per-role config. **App-side fallback loop** (per-attempt audit ledger). MVP dev default `google/gemini-3-flash-preview`. | 0004, 0010, 0015 |
| **Languages** | Python 3.12 backend (agent, API, worker, MCP). Next.js 15 + TS frontend only. | 0005 |
| **Multi-tenancy** | Soft — `tenant_id` column + Postgres RLS. Hard tenancy deferred month 6. | 0006 |
| **Standards** | OCSF 1.3.0 + MITRE ATT&CK enforced end-to-end. | 0007 |
| **Writeback** | Per-tenant `writeback_mode`. `dual` (ES tenants): `siem_notable_update` REST + `siem_hec_post`. `hec_only` (base Splunk, default): HEC only; `notable_update` is no-op. | 0008, 0018 |
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
| `investigation` | **active** | `google/gemini-3-flash-preview` | `anthropic/claude-opus-4-7` | Tier 2 agent loop (LangGraph + MCP tools) |
| `review` | **active** | `google/gemini-3-flash-preview` | `anthropic/claude-sonnet-4-6` | Critic on draft verdict before HITL |
| `summarize` | defined, disabled | — | `anthropic/claude-haiku-4-5` | Human-readable summary for Splunk + UI (post-MVP) |
| `entity_extraction` | defined, disabled | — | `anthropic/claude-haiku-4-5` | OCSF normalization assist (post-MVP) |

Production defaults are *seed-row defaults*, not hardcoded. Bump via new seed rows or admin UI (no doc edit required).

Each row has: `primary_model`, `fallback_chain[]`, `max_tokens`, `temperature`, `timeout_seconds`, `enabled`. **App-side fallback loop** (`apps/orchestrator/src/llm/router.py`) iterates `[primary, *fallback_chain]` and logs each attempt to `usage` table. See ADR-0015.

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
  -- Splunk writeback mode (ADR-0018). Default 'hec_only' (works on plain Splunk Enterprise).
  -- Tenants with Splunk ES installed flip to 'dual' for inline notable_update.
  writeback_mode TEXT CHECK (writeback_mode IN ('dual','hec_only')) DEFAULT 'hec_only',
  -- Sovereignty hybrid surface (ADR-0016). Dormant in MVP; activated when sovereign-mode tier ships.
  byo_openrouter_key_encrypted BYTEA,    -- if set, used instead of master key
  byo_anthropic_key_encrypted BYTEA,     -- for direct Anthropic routing post-MVP
  llm_region_constraint TEXT,            -- 'au-southeast' | 'us-east' | NULL=any
  langsmith_enabled BOOLEAN DEFAULT TRUE,
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

-- Hash-chained append-only audit log (ADR-0017)
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  investigation_id UUID,
  actor TEXT,                            -- user email | 'system' | 'agent:role'
  action TEXT,                           -- llm_call | tool_call | user_approve | ingest | role_config_change
  details JSONB,
  content_hash TEXT,                     -- computed by BEFORE INSERT trigger
  previous_hash TEXT,                    -- chain pointer; computed by trigger
  hash_scope TEXT,                       -- chain partition: 'investigation:<uuid>' | 'tenant:<uuid>'
  created_at TIMESTAMPTZ DEFAULT NOW()
);
-- BEFORE INSERT trigger computes content_hash + previous_hash from prior row in same hash_scope.
-- BEFORE UPDATE/DELETE triggers raise exception ('audit_log is append-only').
-- audit_writer DB role: GRANT INSERT, SELECT only. App role inherits.

-- LLM usage for chargeback. App-side fallback loop logs each attempt, including failures (ADR-0015).
CREATE TABLE usage (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  investigation_id UUID,
  role TEXT,                             -- which role made the call
  attempt_num INT,                       -- 1 = primary, 2+ = fallback (loop in apps/orchestrator/src/llm/router.py)
  model_requested TEXT,                  -- what we asked for
  model_used TEXT,                       -- what OpenRouter served (matches model_requested for explicit single-model calls)
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

-- RLS — strict policy (USING + WITH CHECK) for tenant-only tables
-- Applied to: users, llm_role_config, incidents, investigations, audit_log, usage
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON incidents
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS — global-capable policy for tables where tenant_id IS NULL means global
-- Applied to: detection_rules, hitl_policies
-- USING allows reads of global rows; WITH CHECK is strict so app-role can't INSERT global rows.
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON detection_rules
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
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
- Splunk client: `splunk-sdk` (PyPI) for search jobs + ES endpoints via `service.post()`. `httpx` for HEC.

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

_Session 1 (2026-04-15 / 16): uv workspace + infra compose + Alembic + checkpointer landed. Commits `ccd090d`, `dffdbed`, `ab9eee8`._
_Session 2 (2026-04-16 / 17): full stack + libs/common + MITRE seed + splunk-setup doc landed. Closes Wk 1._

- [x] Repo layout + `.gitignore`, `README.md` stub.
- [x] `docker-compose.yml` with all service stubs building + starting.
- [x] Postgres + Alembic + initial migration (all tables above).
- [x] `langgraph-checkpoint-postgres` `setup()` — checkpointer tables created.
- [x] Seed MITRE STIX → `mitre_techniques` table. _691 techniques; idempotent upsert seeder at `db/seeds/seed_mitre.py`._
- [x] **Load Splunk BOTS v3 into local Splunk.** _Documented in `docs/splunk-setup.md` §6; founder-run on Splunk box._
- [x] `structlog` → stdout JSON wired in all services. _Via `sentient_common.logging.configure_logging`._
- [x] Dev bypass auth flag (`DEV_BYPASS_AUTH=1`) in FastAPI + Next.js middleware.
- [x] Fernet key generation + `.env.example` documented. _Helper at `libs/common/src/sentient_common/crypto.py` with tamper + missing-env tests._
- [x] LangSmith project + API key wired. _`apps/orchestrator/src/sentient_orchestrator/tracing.py` gates on `LANGSMITH_TRACING` + `ls__`-prefixed key._
- [x] `docker compose up` brings up empty-but-healthy stack. _Full stack: postgres + redis + minio + traefik + api + orchestrator + worker + mcp-splunk + web._

**Wk 2 — MCP SIEM server v1 + framework validation**

_Session-start prereqs (founder-run before Claude touches wk 2 code):_

- [x] Fill `.env` real values: `SPLUNK_HOST`, `SPLUNK_TOKEN`, `SPLUNK_HEC_HOST`, `SPLUNK_HEC_TOKEN`, `OPENROUTER_API_KEY`, `LANGSMITH_API_KEY` (`lsv2_` prefix accepted; `ls__` legacy form too), `LANGSMITH_TRACING=true`. **Also `SPLUNK_VERIFY_TLS=false` (founder's box uses self-signed cert).** Closed 2026-04-27.
- [~] BOTS v3 — wk-1 review claimed loaded but Gate 2 query against `index=botsv3` returned 0 events; index doesn't exist. `main` has live UniFi logs (12M events) + Windows event logs from current host. **Action before wk 5 eval set:** founder runs `docs/splunk-setup.md` §6 BOTS load + verifies with `search index=botsv3 earliest=2018-08-01T00:00:00 latest=2018-09-30T00:00:00 | head 1`. Wk-3 OCSF mapper does NOT depend on BOTS.
- [x] Network reachability from docker host verified by Gate 2: 192.168.0.x:8089 connects + auth + oneshot search round-trip. HEC :8088 reachability deferred to wk 8 (`siem_hec_post`); same network/host, low risk.

_Carry-over from wk 1 (non-blocking; resolve opportunistically):_

- [ ] Traefik Docker-provider doesn't read container labels on Docker Desktop for Mac. Pick one fix: (a) Docker Desktop → Settings → Advanced → enable "Allow the default Docker socket to be used", then `docker compose restart traefik`; or (b) add `tecnativa/docker-socket-proxy` sidecar. Host ports in `docker-compose.override.yml` currently work around it. _Punt to wk 9 if not needed for wk-2 dev._
- [x] `splunk-sdk` (PyPI) — update `CLAUDE.md` + `docs/context/stack-locks.md` when the dep lands (currently both say `splunk-sdk-python`). _Done wk 2 Step 0; also removed stale "hybrid" LLM routing row from CLAUDE.md that contradicted ADR 0004._

_Wk 2 work (file-side complete 2026-04-27; founder live-gates pending):_

- [x] Python MCP server (`mcp` official SDK) exposing `siem_query`, `siem_get_notable` backed by Splunk — replaces the `/health`-only FastAPI stub at `mcp/splunk/src/sentient_mcp_splunk/main.py`. **Transport locked to `streamable_http` (ADR-0019).**
- [x] Splunk client: `splunk-sdk` Service for search jobs + auth/session. Cached singleton `SplunkClientFactory` at `mcp/splunk/src/sentient_mcp_splunk/splunk_client.py`. Wk-4 boundary: refactor `get(...)` to `get(tenant_id)` for per-tenant Fernet-decrypted tokens.
- [x] Pydantic tool-contract schemas (`SiemQueryInput`/`Output`, `SiemEvent`, `SiemGetNotableInput`/`Output`) + golden tests scaffolded via `syrupy` (founder runs `-m integration` on box to capture snapshots).
- [x] Unit tests for both tools — 55 tests covering schemas, normalize_spl, dict_to_event, all 5 error mappings (auth, timeout, 4xx, 5xx, internal), found/not_found/degraded paths.
- [x] **Verify: LangGraph + ChatOpenAI-pointed-at-OpenRouter + `langchain-mcp-adapters` + `PostgresSaver` all integrate.** 3-node verify graph at `apps/orchestrator/src/sentient_orchestrator/verify/graph.py`; CLI `python -m sentient_orchestrator.verify`; pytest at `apps/orchestrator/tests/test_verify_smoke.py`. **Founder runs live OpenRouter+LangSmith smoke to close.**
- [x] **Verify: OpenRouter structured output + tool_use passthrough** with Gemini 3 Flash. Covered by the verify graph's `extract_ip` (structured output) + `call_echo_tool` (tool_use) nodes. **Founder live-runs to close.**
- [x] OCSF 1.3.0 validator library spike: hand-rolled Pydantic v2 chosen (ADR-0020 supersedes ADR-0007 §validator). `libs/ocsf/src/sentient_ocsf/detection_finding.py` ships `DetectionFinding` (class_uid 2004) + nested objects + Sentient extensions + `to_hec_dict()` namespacer. 14 tests passing.

_Wk-2 founder live-gates — all PASSED 2026-04-27 (see `tasks/lessons.md` for findings):_

- [x] **Day 1 framework gate** — exit 0; `structured_output_ok=true`, `tool_call_count=1`, `checkpoint_count=5`, `src_ip=10.0.0.42`, `echo_result="echoed: ip=10.0.0.42"`, `langsmith_enabled=true`. LangSmith project = "cyber ai triage". One in-session bug fix: `runner.py`'s independent `langsmith_enabled` check still used the legacy `ls__` prefix; aligned with `tracing.py` after first run reported `langsmith_enabled=false` while traces were actually shipping.
- [x] **Day 2 Splunk SDK smoke** — Splunk 10.0.2 on Ubuntu reachable at 192.168.0.x:8089. `service.info` + 20 indexes listed. Required two env-level overrides documented in lessons: `SPLUNK_VERIFY_TLS=false` (self-signed cert) and replacing `-100y` time ranges with bounded windows (Splunk 10.0.2 rejects `-100y` with HTTP 400). **BOTS v3 was NOT loaded** despite wk-1 claim — `index=botsv3` doesn't exist; `main` has live UniFi logs. Updated integration tests to skip BOTS-dependent paths cleanly + added `test_internal_basic_query` BOTS-independent smoke.
- [x] **Day 5 transport gate (docker)** — `docker compose build mcp-splunk` + `up -d` succeeded; container healthy in 5s; `/health` 200; `splunk_smoke --invoke` runs `siem_query("index=_internal | head 5", "-1h", "now")` end-to-end through the container against the LAN Splunk box. tool_count=2 confirmed, MCP protocol 2025-11-25 negotiated, full request → splunk-sdk → Splunk → response round-trip green.

**Wk 3 — OCSF normalization layer**
- [x] Splunk notable → OCSF 1.3.0 Detection Finding mapper. Lives at `libs/ocsf/src/sentient_ocsf/splunk_mapper.py` (consumes ADR-0020 hand-rolled validator). Single function `map_notable_to_ocsf(notable, *, finding_uid, received_at_ms=None)`; accepts `SplunkNotable | dict` so wk-4 webhook can pass raw JSON.
- [x] Validator per wk 0 decision — resolved wk 2 (ADR-0020 hand-rolled Pydantic v2; supersedes ADR-0007 §validator).
- [x] Store raw + OCSF-normalized payloads in `incidents` table — `raw_payload_s3_key` + `ocsf_normalized` JSONB **already shipped in initial migration `81e2d43b3ec0` lines 95–96**. NOT-NULL guard deferred to wk 4 once the ingest webhook backfills every row. MinIO upload helper (`libs/common/storage.py`) deferred to wk 4 — its bytes-to-key contract belongs with the first caller.
- [x] Unit tests covering ≥10 Splunk notable variants. 12 hand-authored fixtures at `libs/ocsf/tests/fixtures/splunk_notables/*.json` (auth_success_windows, auth_failure_brute_force, endpoint_malware_hash, endpoint_powershell_4104, network_dns_tunnel, network_no_actor, proxy_c2_beacon, cloud_aws_iam, dlp_data_exfil, email_phish, degraded_minimal, malformed_urgency). 85 tests total in `libs/ocsf/tests/`; ruff/black/mypy --strict clean.
- [x] Mapper extension surface: added `Actor`, `User`, `NetworkEndpoint` sub-models + 3 optional fields on `DetectionFinding` (`actor`, `src_endpoint`, `dst_endpoint`). Deferred `Device`, `File`, `Process`, `Evidences[]`, `Enrichments[]` to wk-6 when the investigation agent's enrichment pipeline forces them.

**Wk 4 — Ingest path end-to-end**

_File-side complete 2026-04-27; founder live-gate (Splunk drop on real box) pending._

- [x] Splunk saved search + alert action → webhook to `/api/incidents/ingest` (with body-field `secret` check). **ADR-0014 §header carrier superseded by ADR-0021** — stock Splunk webhook alert action does not support custom headers; secret travels in body. `splunk-setup.md` §5.3 updated with templated `{secret, result}` payload.
- [x] Job enqueue on Redis; worker picks up. `IngestJob` schema + `enqueue_investigation()` live in `libs/common/src/sentient_common/jobs.py` so api producer + worker consumer share the contract without dragging each other's deps.
- [x] Worker invokes orchestrator (stub verdict for now). In-process import: `sentient_orchestrator.stub_investigation.run_stub_investigation(job)`. Wk-6 swaps the body for the real LangGraph runner — import path is stable.
- [x] Smoke: drop notable → investigation row appears with stub verdict. `evals/harness/test_wk4_smoke.py` (`@pytest.mark.integration`) drives the full webhook → MinIO → Postgres → Redis → worker → stub investigation loop. Founder runs against compose stack on box.

**Wk 5 — Per-role LLM config + Triage**

_File-side complete 2026-04-27; founder live-gate (real OpenRouter call against the box) pending._

- [x] Seed `llm_role_config` with 5 rows per tenant (3 enabled, 2 disabled). `db/seeds/seed_llm_role_config.py` — idempotent `INSERT … ON CONFLICT (tenant_id, role) DO NOTHING`. Dev defaults: `google/gemini-3-flash-preview` primary, empty fallback_chain (fail loud in dev), per-role max_tokens / temperature / timeout.
- [x] **`LLMRouter` wrapper** at `apps/orchestrator/src/sentient_orchestrator/llm/router.py` (path corrected from ADR-0015 to match orchestrator package layout). Reads sovereignty cols from `tenants` at construction (`byo_openrouter_key_encrypted` Fernet-decrypted, `llm_region_constraint` passed through to OpenRouter `provider`, `langsmith_enabled` cached). Iterates `[primary, *fallback_chain]`; per attempt: catches `httpx.TimeoutException` → `'timeout'`, `httpx.HTTPStatusError` → `'5xx'` / `'rate_limited'` / `'validation_fail'`. 401/403 → don't retry, propagate. All exhausted → `FallbackChainExhausted(role, attempts)`.
- [x] Usage tracker — `apps/orchestrator/src/sentient_orchestrator/llm/usage.py`. `log_usage_attempt(conn, …)` INSERTs one row per attempt (success + failure) inside the caller's `tenant_session`. Captures `attempt_num`, `model_requested`, `model_used`, status, token counts, `cached_tokens` (parsed from `prompt_tokens_details`), `cost_usd` (from `usage.cost`, NULL if upstream omitted), `openrouter_generation_id`, `latency_ms`.
- [x] Tier 1 classification prompt with OCSF input. `apps/orchestrator/src/sentient_orchestrator/triage/prompt.py` — `SYSTEM_PROMPT` + `build_user_message(finding, mitre_descs)`. Pulls title, desc, severity_id name, actor.user.name, src/dst NetworkEndpoint, attacks[], mitre_techniques[]. MITRE descriptions injected from `mitre_techniques` cache via new `apps/orchestrator/src/sentient_orchestrator/mitre_lookup.py`.
- [x] Pydantic-validated output; 1 retry on schema fail within attempt. `TriageOutput` (`severity` Literal[5], `confidence` 0-100, `mitre_guesses` regex-validated, `entities_to_investigate`, `reasoning`). Router's schema-retry path appends a corrective user message + re-calls SAME model once before bailing to next model with `status='validation_fail'` (the retry doesn't increment `attempt_num`).
- [x] Low/info verdicts auto-close without Tier 2. `apps/orchestrator/src/sentient_orchestrator/runner.py` (renamed from `stub_investigation.py`) — `async run_investigation(job)`. Severity ∈ `{info, low}` → `verdict='benign'`, `incidents.status='done'`, audit `triage_auto_close`. Severity ≥ medium → `verdict='inconclusive'`, `inconclusive_reason='tier_2_pending_wk6'`, leave `incidents.status='triaging'` (wk-6 LangGraph claims `triaging` rows). `FallbackChainExhausted` → `incidents.status='inconclusive'`, audit `triage_failed_fallback_exhausted`.
- Worker dispatch: `asyncio.run(run_investigation(job))` in `apps/worker/src/sentient_worker/main.py`. Worker also calls `init_tracing()` at startup so LangSmith env vars propagate to runner-side calls.
- Tests: 235 unit/contract green (was 175 wk-4); ruff + mypy --strict clean across 54 source files. New: 10 OpenRouter client tests, 14 LLMRouter tests, 9 TriageOutput tests, 7 prompt-builder tests, 8 runner tests, 8 mitre_lookup tests; updated worker dispatch tests for the new in-process async hook.
- Integration smoke: `evals/harness/test_wk4_smoke.py` updated (no longer asserts stub verdict; now requires `OPENROUTER_API_KEY` + asserts triage_started + one of triage_auto_close / triage_escalated / triage_failed_fallback_exhausted in the audit chain + ≥1 `usage` row).

**Wk 6 — Tier 2 LangGraph skeleton + parallel labeling begins**

_File-side complete 2026-04-27; founder live-gate pending. Plan: `/Users/kaya/.claude/plans/plan-next-phase-refactored-star.md`._

- [x] StateGraph skeleton: `plan → execute_tools → correlate → draft_verdict` (no HITL/review yet). `apps/orchestrator/src/sentient_orchestrator/investigation/graph.py` — `plan → agent ⇄ tools (loop) → correlate → draft_verdict`. `route_after_agent` short-circuits to `correlate` when `tool_call_count >= MAX_TOOL_CALLS=10`.
- [x] MCP tools wired via `langchain-mcp-adapters`. `mcp_client.build_mcp_client()` returns a `MultiServerMCPClient` over `streamable_http` (ADR-0019). `tools_node` dispatches each `tool_call` manually with `_extract_tool_text` + `walk_and_sanitize` on results.
- [x] System prompt: MITRE context, OCSF output contract, investigative methodology. `investigation/prompt.py::build_system_prompt(mitre_descs)` injects T-code descriptions; `build_initial_user_message` sanitizes every Splunk-controlled field through the wk-6 `sanitizer` layer.
- [x] `PostgresSaver` checkpointer wired. Crash-resume smoke test. `runner.run_tier2_investigation` opens `AsyncPostgresSaver.from_conn_string(_strip_psycopg_dsn(DATABASE_URL))`. `test_investigation_smoke.py::test_investigation_smoke_resumes_after_inject_failure` proves `plan_node` does NOT re-fire after `INVESTIGATION_INJECT_FAILURE=correlate` (same load-bearing invariant as wk-2 verify).
- [x] Runs visible in LangSmith with full trace + replay. `LLMRouter._build_traced_call` wraps every LLM call in `langsmith.traceable`; `init_tracing()` already sets `LANGCHAIN_TRACING_V2=true` at worker boot. No additional wiring needed.
- [ ] **Start labeling golden set (~2 hrs this week, target ~5 incidents).** _Founder workstream, parallel._

_Wk-6 founder live-gates pending — same flow as wk-5:_

- [ ] **Day 5 end-to-end gate** — drop a medium+ severity notable; assert `incidents.status='done'`, `investigations.verdict ∈ {true_positive,false_positive,benign}`, `langgraph_thread_id` non-NULL, `ocsf_output` JSONB populated, audit chain `triage_started → triage_escalated → investigation_started → llm_call×N → tool_call×M → verdict_drafted → investigation_complete`, ≥4 `usage` rows. LangSmith project shows full graph trace.
- [ ] **Crash-resume gate** — run `pytest -m integration apps/orchestrator/tests/test_investigation_smoke.py` against the box (requires real DB + OpenRouter; mocks MCP). Both tests should pass.

**Wk 7 — Tier 2 completeness + Review role + prompt caching**

_File-side complete 2026-04-27; founder live-gate (real OpenRouter run + MinIO check on the box) pending. Plan: `/Users/kaya/.claude/plans/plan-next-phase-unified-pinwheel.md`._

- [x] Prompt caching (`cache_control` on system + incident + MITRE blocks). `apps/orchestrator/src/sentient_orchestrator/llm/openrouter.py::_apply_cache_markers` rewrites messages flagged `cacheable=True` into Anthropic ephemeral cache-block wire shape (str → 1-block content array with `cache_control:{type:ephemeral}`); `plan_node` flags system + initial-user. Gemini/OpenAI ignore the marker; Anthropic-via-OpenRouter honors it. Cache-hit rate surfaces in evidence manifest `token_usage.cache_hit_rate` (= cached_tokens / input_tokens across success rows); LangSmith already captures per-call `cached_tokens`. **Diagnosis (<50%)** stays a founder-time check on Anthropic-prod runs.
- [x] Evidence manifest format implemented; `evidence.json` to MinIO per investigation. `apps/orchestrator/src/sentient_orchestrator/investigation/evidence.py` — `build_evidence_manifest(...)` + `upload_manifest(...)`. Pulls agent_turns from final_state, tool_calls from `audit_log` (SHA256 hashed result_summary; `result_s3_key=null` until wk-8/9), token_usage + attempts from `usage`. Key `manifests/{tenant_id}/{investigation_id}.json` (deterministic, idempotent overwrite on resume). `evidence_s3_key` column reused (already on initial schema). MinIO failure does NOT roll back the verdict — caught + audit-emitted as `manifest_upload_failed`.
- [x] Per-investigation token/cost caps (abort to inconclusive if exceeded). New migration `c1d8e3f4a9b2_wk7_cost_cap_review` adds `total_input_tokens` / `total_output_tokens` / `total_cost_usd` columns on `investigations` + `per_investigation_token_cap` on `tenants` (USD cap already there). `LLMRouter._check_budget` does a single pre-call SELECT before the fallback loop and raises `BudgetExceeded` if either cap is exceeded; `update_investigation_totals` UPDATEs the running totals atomically after each successful attempt (COALESCE on NULL `cost_usd`). Runner exception handler routes `BudgetExceeded` → `_finalize_inconclusive(reason='budget_cap_exceeded')` + emits `budget_exceeded` audit. Known gap (existing wk-6 issue): `_validate_with_retry`'s second HTTP call doesn't log a usage row, so its tokens/cost are absent from the cap. Documented in code comment + carry-over.
- [x] **`review` role wired.** Per CLAUDE.md + ADR locks, `review_node` sits AFTER `draft_verdict` (annotation-only — never overrides verdict/confidence). `ReviewOutput` Pydantic schema (`status`, `hallucination_risk`, `confidence_assessment`, `notes`, `flagged_claims[]`). Graph edge: `correlate → draft_verdict → review → END`. Failures inside `review_node` (FallbackChainExhausted / BudgetExceeded / unhandled) yield `status='skipped'` with reason — DO NOT propagate; verdict already drafted. Persisted to `investigations.review_status` / `review_notes` / `review_metadata`. Audit emits: `review_started`, `review_complete`, `review_skipped`. `review` row already in `seed_llm_role_config.py` so no seed change.
- [ ] **Continue labeling (~2-3 hrs, target ~10 more incidents).** _Founder workstream, parallel._

_Wk-7 founder live-gates pending — same flow as wk-6:_

- [ ] **Day 5 unified e2e gate** — drop a medium+ severity notable; assert `incidents.status='done'`, `investigations.{verdict,review_status,review_notes,total_cost_usd,total_input_tokens,total_output_tokens,evidence_s3_key,langgraph_thread_id}` non-NULL. Audit chain: `triage_started → triage_escalated → investigation_started → llm_call×N → tool_call×M → verdict_drafted → review_started → review_complete → investigation_complete → manifest_uploaded`. ≥4 `usage` rows. MinIO `evidence` bucket has `manifests/<tenant_id>/<investigation_id>.json`. LangSmith trace shows `review` span.
- [ ] **Cap test** — set `tenants.per_investigation_budget_usd = 0.0001`, drop another notable, assert `verdict='inconclusive'` + `inconclusive_reason='budget_cap_exceeded'` + `budget_exceeded` audit row. Reset cap.
- [ ] **Crash-resume gate** — run `pytest -m integration apps/orchestrator/tests/test_investigation_smoke.py` against the box (real DB + OpenRouter; mocks MCP). Resume should land on the new `review` node (or a later one) but never re-fire `plan`.

**Wk 8 — Detection rules + HITL + dual writeback**

_File-side complete 2026-04-27; founder live-gate (real Splunk + OpenRouter on the box) pending. Plan: `/Users/kaya/.claude/plans/plan-next-phase-reactive-pascal.md`._

- [x] `apply_detection_rules` graph node; seed 10 rules. Engine at `apps/orchestrator/src/sentient_orchestrator/investigation/detection_rules.py` (DetectionRule + RuleMatch + evaluate_rules + effective_severity + load_enabled_rules_for_tenant). Seed at `db/seeds/seed_detection_rules.py` (idempotent UPSERT against partial unique index). Node `apply_detection_rules_node` in `nodes.py`; mutates `draft_verdict.severity` only when a rule's override is higher.
- [x] `hitl_policies` evaluator (~50 line JSONB tree walker). Default policy `{"op": "always_true"}`. Module `apps/orchestrator/src/sentient_orchestrator/investigation/hitl_policy.py` — 12 operators (`and`/`or`/`not`/`always_true`/`always_false`/`eq`/`gt`/`lt`/`gte`/`lte`/`in`/`contains`), max-depth guard (16), missing-key short-circuit to False (no raise). Default seed at `db/seeds/seed_hitl_policies.py` (global `default_require_approval` priority 1000).
- [x] `await_approval` node using LangGraph `interrupt()`. State persists in checkpointer; resume on analyst click. `await_approval_node` in `nodes.py` — flips `incidents.status='awaiting_approval'` + `investigations.approval_status='pending'` BEFORE `interrupt()` (idempotent SQL UPDATE on resume re-fire), defensively coerces resume payload (bool/UUID/sanitized notes ≤1024 char). CLI hack at `apps/orchestrator/src/sentient_orchestrator/cli_resume.py` for wk-8 testing (wk-9 web UI replaces).
- [x] `siem_notable_update` MCP tool — `service.post('notable_update', ...)` via SDK low-level. ES-only with `degraded=true` on plain Splunk (re-uses wk-2 `_has_notable_index` cache from `siem_get_notable`). Schema at `mcp/splunk/src/sentient_mcp_splunk/schemas/siem_notable_update.py`; tool at `tools/siem_notable_update.py`. 5 error mappings + 9 unit tests.
- [x] `siem_hec_post` MCP tool — `httpx` POST to `/services/collector/event` → `triage_verdicts` index. Async httpx client (NOT splunk-sdk), reads `SPLUNK_HEC_HOST/PORT/TOKEN` + `SPLUNK_VERIFY_TLS` from settings. 8 unit tests + 1 integration (skipped on placeholder env). Schema at `schemas/siem_hec_post.py`; tool at `tools/siem_hec_post.py`. Both tools registered in `server.py`.
- [x] Writeback node `writeback_node` in `nodes.py`. Always HEC; conditional `notable_update` when `tenants.writeback_mode='dual'` AND `incidents.siem_notable_id` non-NULL. Best-effort: never raises, never rolls back the verdict; failure → `writeback_status='failed'` + `writeback_failed` audit. Skipped path on `approval_status='rejected'`. 8 unit tests.
- [x] Migration `d3a9f2c1e7b4_wk8_writeback_approval` — 6 cols on `investigations` (writeback_status, writeback_attempts, approval_status, approver_id, approval_notes, detection_rule_matches) + 4 partial unique indexes on detection_rules + hitl_policies (per-tenant + global namespaces).
- [x] Graph + runner wiring. `graph.py` adds `review → apply_detection_rules → await_approval → writeback → END`. `runner.py` adds `_is_interrupted` (defends both `__interrupt__` channel AND `approval_status='pending'`); extracts `_finalize_after_graph` so cli_resume calls the same finalize path. `_update_investigation_wk8_surface` writes the 6 new cols + populates `human_approved_by/at` when approver_id is a real UUID.
- [x] `evidence.py` carry-forward fix — `rule_matches: []` placeholder now reads `final_state["detection_rule_matches"]`. Manifest schema unchanged (additive).
- [x] 6 new audit emitters in `audit.py` (detection_rules_evaluated, awaiting_approval, approval_received, writeback_attempted, writeback_succeeded, writeback_failed). All sanitized + 1KB-capped.
- [ ] Verify both in Splunk: original notable gets comment + new event in triage_verdicts. _Founder live-gate workstream._
- [ ] **Continue labeling (~2-3 hrs, target ~10 more incidents).** _Founder workstream, parallel._

_Wk-8 founder live-gates pending — same flow as wk-6/7:_

- [ ] **Day 5 unified e2e gate** — drop a medium+ severity notable; assert `incidents.status='awaiting_approval'` + `investigations.approval_status='pending'` after triage + investigation. Audit chain ends with `awaiting_approval`. LangSmith trace shows `apply_detection_rules` + `await_approval` spans.
- [ ] **Auto-approve gate** — set the global default policy to `{"op":"always_false"}` via SQL; re-drop. Assert `approval_received` audit with `approved=true notes=auto_approved`. Reset to `always_true` after.
- [ ] **CLI resume** — `uv run python -m sentient_orchestrator.cli_resume --investigation-id <id> --approve --analyst-id <uuid> --notes "looks good"`. Assert `incidents.status='done'`, `investigations.{verdict, writeback_status='succeeded'}`. Audit extends with `approval_received → writeback_attempted → writeback_succeeded → investigation_complete`.
- [ ] **Splunk verification** — HEC: `index=triage_verdicts | head 5` shows OCSF event with `sentient_verdict` populated. `notable_update` (`writeback_mode='dual'` only): original notable gets the verdict comment + status flipped to `in_progress`. On `hec_only` tenant audit shows only one `siem_hec_post` attempt.
- [ ] **Cap test (wk-7 regression)** — set `tenants.per_investigation_budget_usd=0.0001`; drop notable; assert `verdict='inconclusive'` + `inconclusive_reason='budget_cap_exceeded'` + `budget_exceeded` audit row, NOT `awaiting_approval`. Reset cap.
- [ ] **Crash-resume gate** — `pytest -m integration apps/orchestrator/tests/test_investigation_smoke.py` against the box; both tests still green after wk-8 graph extension.

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

### Wk 8 Review

**Session 1 (2026-04-27) — file-side complete; founder live-gate pending.**

Landed (committed `9967c16` for wk-7 first; wk-8 changes uncommitted at end of session; 488 tests passing, ruff + mypy --strict clean across 78 source files):

**Migration `d3a9f2c1e7b4_wk8_writeback_approval`** — 6 cols on `investigations` (writeback_status CHECK IN ['pending','succeeded','failed','skipped'], writeback_attempts JSONB DEFAULT '[]', approval_status CHECK IN ['pending','approved','rejected','auto'], approver_id UUID, approval_notes TEXT, detection_rule_matches JSONB) + 4 partial unique indexes split per-tenant + global namespaces on detection_rules + hitl_policies. Verified live: `alembic upgrade head` clean; `\d investigations` shows all 6 cols + check constraints + writeback_attempts default.

**Detection rules engine** (`apps/orchestrator/src/sentient_orchestrator/investigation/detection_rules.py`) — `DetectionRule` + `RuleMatch` dataclasses (frozen). `evaluate_rules(rules, *, mitre_techniques)` matches on `required_techniques` (AND) + optional `any_techniques` (OR). `effective_severity(agent, matches)` is max-rank (never lowers). `load_enabled_rules_for_tenant(conn, tenant_id)` SELECTs `WHERE enabled AND (tenant_id = :tid OR tenant_id IS NULL)` (own + global). 14 unit tests + 1 integration (skipped on non-seeded DB).

**10 seeded global rules** (`db/seeds/seed_detection_rules.py`) — verified against `mitre_techniques` (691 rows). `ransomware_kill_chain` (T1059.001+T1486 / T1071…) → critical, `credential_dumping_then_lateral` (T1003+T1021 / T1021.001…) → critical, `interactive_privilege_escalation` (T1078+T1068) → high, `defense_evasion_clearlogs` (T1070.001 / T1059.001…) → high, `cloud_iam_persistence` (T1098.003 / T1078.004) → high, `data_exfil_over_c2` (T1041 / T1071…) → critical, `phishing_with_macro` (T1566.001+T1204.002 / T1059.005) → high, `living_off_the_land_proxy_chain` (T1218.011 / T1059.001…) → medium, `webshell_persistence` (T1505.003 / T1190) → high, `valid_accounts_only` (T1078) → low (floor only — never escalates).

**HITL policy evaluator** (`apps/orchestrator/src/sentient_orchestrator/investigation/hitl_policy.py`) — pure-Python, no `eval`/`exec`, allowlisted operators only. 12 ops (`and`/`or`/`not`/`always_true`/`always_false`/`eq`/`gt`/`lt`/`gte`/`lte`/`in`/`contains`). Max-depth 16 (raises ValueError beyond). Missing-key short-circuit to False (never raises on probe of optional ctx field). Boolean operands rejected for numeric compare (caught → False). `select_active_policy(conn, tid)` returns highest-priority enabled policy (tenant wins over global at same priority via NULLS LAST); fallback default = `{"op": "always_true"}`. 13 unit tests.

**Default global HITL policy** (`db/seeds/seed_hitl_policies.py`) — `default_require_approval`, expression `{"op":"always_true"}`, priority 1000. Per ADR-0009: MVP = 100% human approval; tenant-specific lower-priority rules can opt out for narrow conditions.

**Three new graph nodes** (`investigation/nodes.py`):
- `apply_detection_rules_node` — loads enabled rules, evaluates matches, mutates `draft_verdict.severity` only when override is higher, emits `detection_rules_evaluated` audit. Returns `{"draft_verdict": {**draft, "severity": new_sev}, "detection_rule_matches": [...]}`.
- `await_approval_node` — `select_active_policy` + `evaluate_policy(ctx)`. Auto-path returns `approval_status='auto'`. Human-required path: SQL UPDATE flips `incidents.status='awaiting_approval'` + `investigations.approval_status='pending'` BEFORE `interrupt(...)` (idempotent on resume re-fire). Resume payload defensively coerced (`bool()`/UUID-str/sanitize+1024-cap).
- `writeback_node` — reads `tenants.writeback_mode` + `incidents.siem_notable_id` per-call (no caching — admin can flip mode mid-investigation). Always HEC; conditional `siem_notable_update` when `dual` AND `siem_notable_id` non-NULL. `_invoke_writeback_tool` catches every exception → `(False, detail)`. Best-effort: never raises, never rolls back. Skipped path on `approval_status='rejected'`. 8 unit tests.

**CLI resume** (`apps/orchestrator/src/sentient_orchestrator/cli_resume.py`) — argparse `--investigation-id`, mutually exclusive `--approve`/`--reject`, `--analyst-id`, `--notes`. Reads `langgraph_thread_id` off DB (bypasses RLS via raw psycopg — dev hack only; wk-9 web UI authenticates), opens `AsyncPostgresSaver`, `await graph.ainvoke(Command(resume={...}), config)`. Exit codes 0/2.

**Two new MCP tools**:
- `siem_notable_update` — schema (notable_id pattern reused from siem_get_notable; comment 1-4096; status enum; urgency enum). Tool: `service.post('notable_update', ...)` via splunk-sdk low-level, wrapped in `asyncio.to_thread` + `wait_for(timeout=15)`. Re-uses `_has_notable_index` cache from wk-2 (exported helper). Error chain: `except SiemToolError: raise` first, then auth/timeout/4xx/5xx/internal. ES-only with `degraded=true` on plain Splunk.
- `siem_hec_post` — schema (event dict required + non-empty validator; sourcetype default `sentient:detection_finding`; index default `triage_verdicts`). Tool: `httpx.AsyncClient` POST to `:8088/services/collector/event` with `Authorization: Splunk <token>`. `splunk_verify_tls` pass-through (founder's box uses self-signed). Error mappings: 401→auth_failure, ≥400→splunk_4xx/5xx, TimeoutException→search_timeout, HTTPError→internal, missing config→internal.

**6 new audit emitters** (`investigation/audit.py`) — `emit_detection_rules_evaluated`, `emit_awaiting_approval`, `emit_approval_received`, `emit_writeback_attempted`, `emit_writeback_succeeded`, `emit_writeback_failed`. All wrap `walk_and_sanitize` + 1KB cap. 6 new unit tests.

**Graph wiring** (`investigation/graph.py`) — full topology now: `START → plan → agent ⇄ tools (cap=10) → correlate → draft_verdict → review → apply_detection_rules → await_approval → writeback → END`. 9 nodes total. Node count test + edge presence test extended.

**Runner finalization** (`investigation/runner.py`) — `_is_interrupted(final_state)` checks both `__interrupt__` channel marker AND `approval_status='pending'` w/o writeback_status (defence-in-depth across LangGraph minor versions). Extracted `_finalize_after_graph` so `cli_resume.py` shares the persistence path. `_update_investigation_wk8_surface` writes 6 new cols + populates `human_approved_by/at` when approver_id is a real users.id UUID. `_finalize_done` extended with 6 wk-8 kwargs (all optional / default-NULL).

**State** (`investigation/state.py`) — 6 new TypedDict fields (detection_rule_matches, approval_status, approver_id, approval_notes, writeback_status, writeback_attempts). `node_call_counts` adds `apply_detection_rules`/`await_approval`/`writeback`.

**Wk-7 carry-forward** — `evidence.py:194-195`: `rule_matches: []` placeholder now reads `final_state["detection_rule_matches"]`. Manifest schema unchanged (additive).

**MCP server registration** (`mcp/splunk/src/sentient_mcp_splunk/server.py`) — both wk-8 tools registered. Tool surface now `{siem_query, siem_get_notable, siem_notable_update, siem_hec_post}`. Wk-2 `test_tool_count_matches_wk2_scope` renamed + bumped to wk-8 expected set; 2 new tool-registration tests (input schema asserts).

Verified end-to-end (this session, no live integrations needed):

- `uv run alembic upgrade head` — wk-7 + wk-8 migrations clean; `\d investigations` shows full surface.
- `uv run python db/seeds/seed_detection_rules.py` → 10 global rules upserted.
- `uv run python db/seeds/seed_hitl_policies.py` → default policy upserted.
- `uv run ruff check apps libs mcp` — clean.
- `uv run mypy apps libs mcp` — 71 source files, no issues.
- `uv run pytest -q` — **488 passed**, 2 skipped (verify smoke), 6 deselected (3 wk-2 + 2 wk-6 integration markers + 1 new wk-8 detection_rules integration marker).

**Architectural decisions surfaced:**
- (new) `_has_notable_index` cache is process-global, NOT per-tenant. Acceptable for wk-8 single-tenant founder box. Per-tenant lands wk-12 with `splunk_client.py` per-tenant refactor (BOUNDARY: do not refactor before).
- (new) `_load_writeback_mode` reads inside `writeback_node` itself (no caching) so an admin flip lands in-flight. Few-second latency acceptable single-tenant; multi-tenant may want a cache with TTL wk-12.
- (carry-forward) `awaiting_approval` rows orphaned forever if analyst never clicks. Wk-12 reaper auto-rejects after 7 days.
- (carry-forward) CLI resume is a developer-only hack — no auth, no audit beyond what the node emits. Wk-9 web UI replaces.
- (new) `_invoke_writeback_tool` parses tool response text for `"success": false` / `"degraded": true` to surface soft failures as audit attempts even when the call didn't raise. Heuristic; may need to unmarshal JSON proper if false-positives surface.

Carry-over to wk-9: web UI investigation detail page (verdict + reasoning trace from manifest + evidence chain + MITRE matrix + review notes), approval button (POST → resume payload into LangGraph thread, replacing CLI hack), audit-log explorer, time-travel replay. The `cli_resume.py` is the contract spec for the wk-9 approval-route handler.

### Wk 6 Review

**Session 1 (2026-04-27) — file-side complete; founder live-gates pending.**

Landed (uncommitted at end of session; 352 tests passing, ruff + mypy --strict clean across 63 source files):

**LLMRouter extension (Day 1)** — additive change to support tool-use:
- `apps/orchestrator/src/sentient_orchestrator/llm/openrouter.py` — added `OpenRouterToolCall(id, name, arguments)` + `OpenRouterResponse.tool_calls: list[OpenRouterToolCall]` + `tools` / `tool_choice` kwargs to `call_chat_completion`. `_parse_tool_calls` parses `choices[0].message.tool_calls`; malformed JSON in `function.arguments` raises `ValueError` (router buckets as `validation_fail`). Empty list when absent.
- `apps/orchestrator/src/sentient_orchestrator/llm/router.py` — `LLMResult.tool_calls: tuple[OpenRouterToolCall, ...]` + new kwargs. Validates `tools` and `response_schema` mutually exclusive. New ValueError-bucket path in `_attempt` (covers malformed tool args + the existing "no choices" defensive raise).
- Tests: 9 new in `test_llm_openrouter.py` (request body shape, `tools`/`tool_choice` pass-through, empty-list parsing, multi-call parsing, malformed-args ValueError, empty-string args, dict args, no-tools no-keys); 4 new in `test_llm_router.py` (pass-through, no-tools kwargs, mutual-exclusion guard, malformed-args fallback). 45 total in those two files.

**Investigation primitives (Day 2)** — new package `apps/orchestrator/src/sentient_orchestrator/investigation/`:
- `state.py` — `InvestigationState` TypedDict (messages reducer, identifiers, triage context, tool_call_count, draft_verdict). `InvestigationOutput` Pydantic (`verdict`/`confidence`/`severity`/`mitre_techniques[]`/`summary`/`evidence[]`/`reasoning`, `extra="forbid"`). `MAX_TOOL_CALLS=10`.
- `sanitizer.py` — `sanitize_untrusted(value, max_chars=4000)` strips C0/C1 + DEL (keeps `\t\n\r`), normalizes CRLF→LF, truncates with `…[truncated]` marker. `walk_and_sanitize(obj)` recurses dict/list values (NOT keys). 25 unit tests covering control-char strip, CRLF normalization, idempotency, encoded-payload pass-through (base64, hex, JSON, escaped quotes), nested walk, scalar pass-through.
- `audit.py` — thin wrappers over `sentient_common.audit.insert_audit_log`. Six emitters: `emit_investigation_started`, `emit_llm_call`, `emit_tool_call` (sanitized + 1KB-capped args/result), `emit_verdict_drafted`, `emit_investigation_complete`, `emit_investigation_failed`. Actor `orchestrator:investigation`. 8 tests assert sanitization + truncation paths.
- `prompt.py` — `build_system_prompt(mitre_descs)` renders 7-section template (role, methodology, tools, MITRE block, output contract, guardrails, trust boundary). `build_initial_user_message(*, finding, triage_ctx, mitre_descs)` formats per-incident user message, sanitizing every OCSF field. 13 tests over `libs/ocsf/tests/fixtures/splunk_notables/*.json`.

**Graph + nodes (Day 3)**:
- `nodes.py` — `plan_node` / `agent_node` / `tools_node` / `correlate_node` / `draft_verdict_node`. Each LLM-calling node opens its own `tenant_session` (short txn) for the `LLMRouter.call` + audit emit, so per-attempt usage rows + audit rows commit independently of the long-running graph. Helpers: `tools_to_openai_schema` (via `langchain_core.utils.function_calling.convert_to_openai_tool`), `find_tool`, `extract_tool_text` (mirrors `verify/graph.py:141`), `_serialize_assistant_message` (re-encodes `tool_calls.arguments` to JSON STRING per OpenAI wire format). `node_call_counts` dict + `INVESTIGATION_INJECT_FAILURE_ENV` for the resume smoke. `route_after_agent` returns `"tools"` only when last assistant has `tool_calls` AND count `< MAX_TOOL_CALLS`. 24 unit tests (mocked LLMRouter + tools).
- `graph.py` — `build_investigation_graph()` returns the StateGraph builder (caller compiles with checkpointer). 4 topology tests confirm node set, edges, and conditional branch on `agent`.

**Runner + main wiring (Day 4)**:
- `mcp_client.py` — `build_mcp_client()` factory; reads `MCP_SPLUNK_URL` env (compose-set). Returns `MultiServerMCPClient` over `streamable_http`. Single-line module — bigger than that is wk-7 territory.
- `runner.py` — `async run_tier2_investigation(*, investigation_id, tenant_id, incident_id) -> None`. Three phases:
  1. **Claim txn** — SELECT investigation row + `inconclusive_reason='tier_2_pending_wk6'` guard, atomic `UPDATE incidents SET status='investigating' WHERE status='triaging'` (rowcount==0 → log + return), generate `thread_id = inv-<hex[:12]>`, mark `langgraph_thread_id` + clear `inconclusive_reason`, audit `investigation_started`. Commit.
  2. **Graph run** — load tools from `build_mcp_client().get_tools()`, open `AsyncPostgresSaver.from_conn_string(_strip_psycopg_dsn(DATABASE_URL))`, compile graph, `ainvoke(initial_state, config={configurable: {thread_id, tenant_id, investigation_id, finding, tools, mitre_descs}})`. `FallbackChainExhausted` + bare `Exception` both finalize as `inconclusive` with audit row.
  3. **Finalize** — new `tenant_session`, write `investigations.verdict / confidence / severity / mitre_techniques / summary / ocsf_output / completed_at`, `incidents.status='done'` (or `inconclusive`), audit `investigation_complete` (or `investigation_failed`).
- `runner.py` (main triage) — restructured: `was_escalated` flag set inside the triage `with tenant_session` block; OUTSIDE the block (after commit), `if was_escalated: await run_tier2_investigation(...)`. Worker dispatch (`apps/worker/src/sentient_worker/main.py`) unchanged — `asyncio.run(run_investigation(job))` already awaits the full chain.
- Tests: 12 new `test_investigation_runner.py` (claim guard, finding+tools threading, FallbackChainExhausted, generic exception, missing DATABASE_URL, missing verdict, helpers); existing `test_runner.py` patched with `patch_tier2` fixture — adds 1 new test confirming `run_tier2_investigation` is invoked after escalation but NOT after auto-close.

**Integration smoke + crash-resume (Day 5)**:
- `test_investigation_smoke.py` — `@pytest.mark.integration`. Two tests, both skip cleanly on placeholder env. Mocks `build_mcp_client` to return static `siem_query` + `siem_get_notable` LangChain tools (real Splunk not required); requires real Postgres + OpenRouter.
  1. `test_investigation_smoke_runs_to_verdict` — seeds incident + investigation rows in wk-5-escalated state (`status='triaging'`, `inconclusive_reason='tier_2_pending_wk6'`), runs `run_tier2_investigation`, asserts terminal status + verdict + audit chain + ≥2 `usage` rows. Tolerates model bailing as `inconclusive` on synthetic evidence (asserts `inconclusive_reason` populated either way).
  2. `test_investigation_smoke_resumes_after_inject_failure` — drives `graph.ainvoke` directly with `INVESTIGATION_INJECT_FAILURE=correlate`, asserts mid-flight node counts. Re-invokes with `ainvoke(None, config)` (resume mode); asserts `plan_node.count == 1` (didn't re-fire — proves checkpoint replay), `correlate.count >= 2`, `draft_verdict.count >= 1`. **Load-bearing wk-6 invariant.**

**Architectural decisions surfaced for later resolution:**
- (carry-forward) Cross-process crash-resume not in scope. Same-process resume proven by smoke test 2; cross-process recovery (Redis already popped, worker died) requires a polling reaper for `status='investigating'` rows — wk-12 hardening.
- (carry-forward) `tenants.max_concurrent_investigations` not enforced. wk-12.
- (carry-forward) Per-investigation token / USD caps. wk-7.
- (new) The Tier-2 `entities` field is not currently round-tripped through the `investigations` table. Wk-5 audit log captures it but the runner can't recover it on Tier-2 resume. Acceptable for skeleton — model can re-extract from the OCSF + reasoning. Wk-7 may add an `investigations.entities text[]` column when the review role wants the full Tier-1 hand-off.
- (new) `LLMRouter._attempt` now buckets ANY `ValueError` from `_parse_response` as `validation_fail` (was: only schema-retry path). Existing "no choices" ValueError path was never exercised in the router tests; this unifies the model-output-broke handling. No regression in 256 pre-wk6 tests.
- (new) `tools_node` includes a tool-call-error-as-ToolMessage fallback (`text = f"error: {type(exc).__name__}: {exc}"`). Lets the agent loop continue past a transient Splunk failure rather than aborting the investigation. Tested.

Verified end-to-end (this session, no live integrations needed):
- `uv run ruff check apps libs mcp` — clean.
- `uv run mypy apps libs mcp` — 63 source files, no issues.
- `uv run pytest -q` — **352 passed**, 2 skipped (verify smoke skips on placeholder OPENROUTER_API_KEY), 5 deselected (3 wk-2 + 2 new wk-6 integration markers).

Carry-over to wk-7: review role node (insert between `correlate` and an eventual `await_approval`), prompt caching `cache_control` on system + incident + MITRE blocks, evidence manifest `evidence.json` to MinIO, per-investigation token/USD caps, eventual unification of LangChain tracing surface (currently agent-loop tool calls don't appear as native LangChain spans — only LLMRouter's traced HTTP calls).

### Wk 0 Review
_Pending._

### Wk 2 Review

**Session 1 (2026-04-27) — file-side complete; founder live-gates pending.**

Landed (uncommitted at end of session):

- `apps/orchestrator/pyproject.toml` deps bumped: `langgraph>=1.1,<2`, `langchain-mcp-adapters>=0.2,<0.3`, `mcp>=1.27,<2`. Dev deps: `pytest-asyncio>=0.24`, `pytest-mock>=3.14`. Installed: langgraph 1.1.6, langchain-mcp-adapters 0.2.2, mcp 1.27.0, pydantic 2.13.0, langchain-openai 1.1.13.
- Verify harness at `apps/orchestrator/src/sentient_orchestrator/verify/`:
  - `echo_mcp_server.py` — stdio FastMCP, single `echo(msg) -> str` tool.
  - `llm.py` — `build_chat_openrouter()` with `default_headers={HTTP-Referer, X-Title}`, `temperature=0`, `max_retries=0`. Documents the wk-2 acceptance of `langchain-openai 1.1.13`'s OpenRouter warning (ADR-0015 LLMRouter takes over wk 5).
  - `schemas.py` — `VerifyState` TypedDict, `ExtractedIP` Pydantic.
  - `graph.py` — 3-node StateGraph (`extract_ip` → `call_echo_tool` → `done`) with `inject_failure` env hook for resume-after-crash testing.
  - `runner.py` — async `verify_run(thread_id)` returns structured summary; uses `AsyncPostgresSaver`.
  - `__main__.py` — CLI; exit codes 0/1/2 (ok / verify-failed / pre-flight-failed).
  - `splunk_smoke.py` — re-usable `streamable_http` round-trip CLI for both Day-2 (empty) and Day-5 (tools-loaded) gates.
- Pytest scaffold at `apps/orchestrator/tests/{conftest,test_verify_smoke}.py`. Skips cleanly when env carries `.env.example` placeholders.
- `mcp/splunk/pyproject.toml` deps reshuffled: dropped `fastapi`; added `mcp[cli]>=1.27`, `splunk-sdk>=2.1`, `pydantic>=2.9`, `pydantic-settings>=2.6`, `anyio>=4.6`, `starlette>=0.40`. Dev deps: `pytest-asyncio`, `pytest-mock`, `syrupy>=4.7`.
- `mcp/splunk/src/sentient_mcp_splunk/`:
  - `main.py` — replaces FastAPI stub; FastMCP `streamable_http_app()` + `@mcp.custom_route("/health")` co-host on the same Starlette ASGI app. Dockerfile + uvicorn target unchanged.
  - `server.py` — `build_mcp() → FastMCP`; tool registration via per-module `register(mcp)` functions.
  - `settings.py` — pydantic-settings env loader.
  - `splunk_client.py` — cached `splunklib.client.Service` singleton with reset on auth failure. Comment block flags wk-4 per-tenant refactor boundary.
  - `errors.py` — JSON-RPC error mapping (`SiemToolError(kind, message)` → MCP `INTERNAL_ERROR` + `data.kind`).
  - `schemas/{siem_query,siem_get_notable}.py` — Pydantic v2 input/output models. `SiemQueryInput` rejects 14 forbidden SPL token forms; `SiemGetNotableInput` `notable_id` regex `^[A-Za-z0-9_:.\-@]+$`.
  - `tools/siem_query.py` — `oneshotsearch` via `asyncio.to_thread`, prepended `search` for non-generators, `JSONResultsReader` parsing, error mapping for 5 splunk-sdk exception types. Tool description block surfaces forbidden-SPL contract to the LLM.
  - `tools/siem_get_notable.py` — degraded-mode for plain Splunk (no `index=notable`) returns `degraded=true` + structured note rather than erroring.
- `mcp/splunk/tests/`:
  - `unit/test_siem_query_schemas.py` (15 tests) — input bounds, forbidden-SPL parametrised, event aliases, time-parse swallow.
  - `unit/test_siem_query_tool.py` (16 tests) — normalize_spl, dict_to_event, happy path, truncation, no-results, message dropping, all 5 error mappings.
  - `unit/test_siem_get_notable.py` (10 tests) — input regex (incl SPL-injection rejection), degraded/found/not_found paths, auth_failure mapping, double-quote SPL safety.
  - `unit/test_server_registration.py` (3 tests) — FastMCP tool surface pinned to `{siem_query, siem_get_notable}`; bumps required when wks 6/8 grow it.
  - `integration/test_live_splunk.py` (3 tests, `@pytest.mark.integration`) — basic BOTS query + 4625 login-failure shape snapshot + DNS stream snapshot via syrupy. Skips when `SPLUNK_HOST` is placeholder.
- `libs/ocsf/`:
  - `pyproject.toml` flipped from `package = false` → hatchling build-backend; `pydantic>=2.9` declared. Workspace member now installable.
  - `src/sentient_ocsf/__init__.py` re-exports the public API.
  - `src/sentient_ocsf/detection_finding.py` — hand-rolled OCSF 1.3.0 Detection Finding (`class_uid 2004`). Nested objects: `Metadata`, `Product`, `FindingInfo`, `Analytic`, `Attack`, `MitreTactic`, `MitreTechnique`. Sentient extensions (`verdict`, `evidence_url`, `mitre_techniques[]`) namespaced to `sentient_*` on `to_hec_dict()`. `validate_detection_finding(payload) → DetectionFinding` for the wk-3 mapper.
  - `tests/test_detection_finding.py` (14 tests) — construction, type_uid auto-derivation + reject-mismatch, confidence bounds, extra-field forbidden, technique uid validation, HEC namespacing, none-exclusion, validator round-trip + class_uid mismatch.
- `pyproject.toml` (root):
  - `[tool.pytest.ini_options]` adds `markers = ["integration: requires live Splunk; founder-box only"]` + `addopts = "-m 'not integration'"` + `asyncio_mode = "auto"`.
  - `[tool.ruff.lint.isort]` sets `known-first-party` to all `sentient_*` workspace modules + `known-third-party = ["mcp"]` (since `mcp/` is also a workspace dir name).
  - `[tool.mypy]` excludes `tests/` dirs (duplicate-module-name collisions across workspace members) + per-module override turning off `disallow_untyped_decorators` for `sentient_mcp_splunk.main` (FastMCP `custom_route` returns an untyped wrapper) + `ignore_missing_imports` for `splunklib.*`.
- `docs/decisions/`:
  - **ADR-0019** (`0019-mcp-transport-streamable-http.md`) — locks `streamable_http`. stdio rejected (single-client, breaks multi-container topology). sse rejected (deprecated MCP spec 2025-03-26).
  - **ADR-0020** (`0020-ocsf-validator-handrolled-pydantic.md`) — supersedes ADR-0007 §validator. Hand-rolled Pydantic v2 vs `py-ocsf-models` (which targets 1.5.0 → drift).
  - `README.md` index updated; ADR-0007 status amended to `(validator §refined by 0020)`.
- `docs/context/stack-locks.md` — Agent-framework + Standards rows updated with `streamable_http` transport lock + `mcp[cli]>=1.27,<2` + hand-rolled OCSF.

Verified end-to-end (this session, on host without live Splunk/OpenRouter):

- `uv run ruff check .` — clean.
- `uv run mypy apps libs mcp` — 37 source files, no issues.
- `uv run pytest -q` — **91 passed**, 2 skipped (verify smoke skips on placeholder OPENROUTER_API_KEY), 3 deselected (integration marker).
- `uv run python -m sentient_orchestrator.verify` — exits 2 with structured "verify aborted" log when LangSmith env not set (correct pre-flight behaviour).
- **Streamable_http transport gate PASSED locally:** uvicorn-launched FastMCP server + `splunk_smoke.py` returns `tool_count=2 names=['siem_query','siem_get_notable']`. MCP protocol version 2025-11-25 negotiated.

**Post-implementation review pass (same session)** caught + fixed 3 P0s + 4 P1s + 1 P2 — captured in `tasks/lessons.md`:

- (P0) `tracing.py` rejected real `lsv2_`-prefixed LangSmith keys (only accepted legacy `ls__`). Founder gate would have failed silently.
- (P0) `init_tracing()` set `LANGSMITH_TRACING` but not `LANGCHAIN_TRACING_V2` — LangChain runnables wouldn't have shipped traces even after the prefix fix.
- (P0) `test_verify_smoke_resumes_after_inject_failure` passed `{"messages": []}` on the second `ainvoke` call — that's a fresh run, not a resume. Reworked: `verify_run(resume=True)` → `ainvoke(None, config)`; tests now also assert `node_call_counts["extract_ip"] == 1` to prove the LLM node didn't re-fire.
- (P1) Forbidden-SPL guard bypassable via `\t` / multi-space whitespace; switched to regex with `\b` boundaries + `re.IGNORECASE`.
- (P1) `siem_get_notable` issued `service.indexes['notable']` REST call every invocation; cached the probe with thread-safe invalidation.
- (P1) `except Exception` could catch already-typed `SiemToolError` and re-wrap as `internal`. Added `except SiemToolError: raise` first in both tool handlers. Removed unused `max_wait` param. Replaced `{"_degraded": True}` dict sentinel with typed `_NotableIndexAbsentError` exception.
- (P1) `tool_choice="echo"` (specific name) rejected by some OpenRouter providers; switched to `tool_choice="any"`. LangSmith URL builder dropped — printed project URL only + filter hint.
- (P2) OCSF `DetectionFinding.type_uid` had class-level constant default → didn't track non-default `activity_id`. Now derived in `model_validator(mode="after")`; mismatched explicit value raises.

Decisions surfaced for later resolution:

- (carry from wk 1) `libs/ocsf` package=false → hatchling — **resolved** wk 2 Day 4.
- (carry from wk 1) Dev-user tenant UUID literal in `apps/api/src/sentient_api/settings.py` — wk 4 wires to seeded `tenants` row.
- (new) `langchain-openai 1.1.13` actively warns against pointing `base_url` at OpenRouter; non-standard fields silently dropped. Acceptable for wk-2 verify; ADR-0015 LLMRouter (wk 5) goes direct httpx and bypasses LangChain's OpenAI wrapper entirely. Captured in `tasks/lessons.md`.
- (new) FastMCP returns content-block lists from `BaseTool.ainvoke()` (`[{type:"text", text:"..."}]` rather than plain strings); `verify/graph.py::_extract_tool_text` flattens for ToolMessage content. Pattern reusable in wk-6 `ToolNode`.
- (new) splunk-sdk's `AuthenticationError(message, cause)` and `HTTPError(response, message)` constructors are non-trivial to mock — `cause` must be itself an `HTTPError`, `response.body` must be a stream not bytes. Captured for future test authors in `lessons.md`.

Carry-over to wk 3: full OCSF Splunk-notable-to-Detection-Finding mapper (`libs/ocsf` consumes the validator landed wk 2; wk 3 adds the Splunk-side mapping + may extend the model with `actor`/`endpoint` objects if real notables surface them).

### Wk 1 Review

**Session 1 (2026-04-15 / 16) — foundational scaffold.**

Landed (commits `ccd090d`, `dffdbed`):
- Baseline commit of 24 planning files.
- uv 0.9.26 workspace: root `pyproject.toml` with `[tool.uv.workspace]` + 5 non-packaged members (`apps/api`, `apps/orchestrator`, `apps/worker`, `mcp/splunk`, `libs/ocsf`). Dev deps in `[dependency-groups] dev`. `uv.lock` committed.
- Next.js 15.5.15 + React 19.1 + Tailwind 4 + TS strict at `apps/web/`; production build verified.
- `docker-compose.yml` infra services (postgres:16, redis:7-alpine, minio/minio) with healthchecks + named volumes; all three report `healthy`.
- Alembic initial migration (`81e2d43b3ec0_initial_schema.py`): 10 app tables + `pgcrypto` extension + 8 RLS policies on tenant-scoped tables using `current_setting('app.current_tenant', true)::uuid` (missing-ok). `alembic.ini` script location set; `env.py` loads `DATABASE_URL` from `.env`.
- LangGraph Postgres checkpointer setup script (`db/seeds/setup_checkpointer.py`) using verified `with PostgresSaver.from_conn_string(...) as cp: cp.setup()` context-manager pattern. Created 4 tables: `checkpoint_migrations`, `checkpoints`, `checkpoint_blobs`, `checkpoint_writes`.
- `.env.example` enumerating all env vars (Splunk remote LAN/VPN, OpenRouter, LangSmith, Anthropic, Fernet, webhook secret, dev-bypass, Postgres, Redis, MinIO).
- `README.md` with quickstart.

Verified end-to-end: `\dt` shows 15 rows (10 app + 4 checkpointer + `alembic_version`); `pg_policies` shows 8 tenant_isolation policies; Next.js `npm run build` passes.

Deferred to session 2 (still Wk 1 scope): MITRE STIX seeder, shared `libs/` utilities (`logging.py`, `crypto.py`, `db.py`), FastAPI/orchestrator/worker/mcp-splunk Dockerfiles + `/health` stubs, full compose with app services, LangSmith orchestrator wire-up, dev-bypass middleware in FastAPI + Next.js, `docs/splunk-setup.md`, BOTS v3 load script.

Decisions surfaced for later resolution:
- Dep name fix: `splunk-sdk` (PyPI), not `splunk-sdk-python` as written in CLAUDE.md / stack-locks. Update when adding the dep in wk 2.
- OCSF validator: current `py-ocsf-models` releases (≥0.5.0) target OCSF 1.5.0. ADR 0007 locks 1.3.0. Resolve at wk 2 spike — default path is hand-rolled Pydantic v2 for Detection Finding (class_uid 2004).
- OpenRouter fallback: resolved 2026-04-27. Verified `route: fallback` is deprecated; canonical syntax is `models[]` array. **However, decision flipped to app-side fallback loop instead** — see ADR-0015. Per-attempt audit ledger requires per-attempt logging which OpenRouter native doesn't expose. Wk 5 wrapper (`apps/orchestrator/src/llm/router.py`) implements explicit single-model calls + retry loop.

**Session 2 (2026-04-16 / 17) — close-out.**

Landed (commits `a0c2301`, `cefe405`, `81177af`, plus this commit):

- `libs/common` uv workspace package `sentient-common` (hatchling build-backend + `py.typed`). Two modules:
  - `logging.configure_logging(service, level)` — structlog processors (`TimeStamper iso UTC`, `add_log_level`, `add_logger_name`, `JSONRenderer`) with stdlib bridge via `ProcessorFormatter` so uvicorn / redis-py / etc. render as the same JSON shape. `service=<name>` injected on every record.
  - `crypto.encrypt`/`decrypt` — Fernet wrapper reading `TENANT_SECRET_KEY`, fails loud on missing/invalid key (ADR 0012).
  - 7 tests pass (round-trip, unicode, tamper, missing-env, invalid-env, JSON-shape, stdlib-bridge).
- Five app service stubs — each with `sentient_common.configure_logging` at import time, its own `pyproject.toml` with real deps + `sentient-common` workspace source, and a multi-stage Dockerfile (uv in builder stage only; runtime `.venv/bin/*` exec-form CMD):
  - `apps/api` — FastAPI + `DevBypassAuthMiddleware` (ADR 0011, 501 on non-allowlisted routes when flag off) + `/health` router. Lifespan-based startup log.
  - `apps/orchestrator` — stub main loop + `tracing.init_tracing()` gated on `LANGSMITH_TRACING=true` AND key starting with `ls__` (refuses `CHANGEME_*` placeholder, never boot-kills on LangSmith failure). Sentinel heartbeat (`/tmp/ready`, 30s cadence) for Docker healthcheck.
  - `apps/worker` — redis `BLPOP sentient:jobs:investigations` loop, same sentinel pattern. `BLPOP` return `cast`ed to satisfy mypy strict.
  - `mcp/splunk` — FastAPI `/health` stub only. Real MCP tools + transport pick (stdio vs SSE) land wk 2.
  - `apps/web` — dev-bypass `middleware.ts` injecting `x-dev-user` header, `next.config.ts output=standalone`, multi-stage node:20-alpine Dockerfile.
- Apps + mcp-splunk flipped from `package=false` to real hatchling build-backends so uv installs them as editable workspace members (required for `sentient_api.main` etc. to be importable at runtime). `libs/ocsf` will need the same flip in wk 3.
- Full `docker-compose.yml`: added `traefik:v3.1` (HTTP-only on :80, dashboard :8090 dev-only) + five app services. Host routing: `app.triage.local` → web:3000, `api.triage.local` → api:8000. Healthcheck anchor + `depends_on: condition: service_healthy` gates everywhere.
- `docker-compose.override.yml`: host-port exposes (5432, 6379, 9000/9001, 8000, 8080), bind-mounts of `src/` dirs, `--reload` on api + mcp-splunk. Web dev-mode intentionally left on the host (standalone image has no node_modules).
- `db/seeds/seed_mitre.py`: fetches `enterprise-attack.json` from `mitre-attack/attack-stix-data` (cached under `db/seeds/cache/`, gitignored), upserts via `ON CONFLICT (technique_id) DO UPDATE`. Re-uses the `_load_dotenv` + SQLAlchemy→psycopg DSN-strip pattern from `setup_checkpointer.py`. Current load: **691 techniques**. Idempotent second run confirmed. Spot-check: `T1059.001` PowerShell, `T1071` Application Layer Protocol, `T1486` Data Encrypted for Impact.
- `docs/splunk-setup.md`: founder runbook — target versions, indexes (`main`, `botsv3`, `triage_verdicts`), HEC token, service account + `sentient_triage_role`, saved-search webhook stub, BOTS v3 manual-load steps, `notable_update` verification curl, network reachability checks, TLS-deferred note.
- `README.md`: quickstart updated with `/etc/hosts` entries, `uv sync --all-packages`, MITRE seed step, curl smoke checks, TLS note.
- `pyproject.toml` root: added `libs/common` workspace member; ruff `extend-exclude = ["db/migrations/versions"]` (Alembic migrations are immutable + contain long SQL strings).
- `.gitignore`: added `db/seeds/cache/`.

Verified end-to-end: `uv run ruff check .` clean; `uv run mypy apps libs mcp` clean on 20 source files; `uv run pytest libs/common/tests -q` 7 passed; `docker compose config` validates; MITRE seeder idempotent at 691 rows against the live compose postgres.

Decisions surfaced for later resolution (carry from session 1 + added this session):

- (carry) `splunk-sdk` PyPI name — apply wk 2 when dep lands.
- (carry) OCSF 1.3.0 validator library choice — wk 2 spike.
- (carry → resolved 2026-04-27) OpenRouter fallback syntax verified; flipped decision to app-side fallback loop. See ADR-0015.
- (new) `libs/ocsf/pyproject.toml` still has `package = false`; flip to hatchling build-backend when wk 3 imports it from the orchestrator.
- (new) Dev-user tenant UUID is a fixed literal in `apps/api/src/sentient_api/settings.py` (`DEV_TENANT_ID`) — wire it to a real seeded row in `tenants` when wk 4 ingest path lands.

Carry-over to wk 2: none. Wk 1 is done.
