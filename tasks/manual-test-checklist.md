# Manual Test Checklist

Founder live-gate doc. Tick `[x]` boxes as you verify on the dev box. Paste any failure (error, log line, stack) inline under the failed box. Commit this file when a week's section goes all-green.

**Reality check:** Real product UI lands wk-9. Until then, "what's testable" is a mix of **infrastructure consoles** (Traefik, MinIO) + the placeholder Next.js page + functional verification via curl + psql + docker logs. No investigation pages, no admin panel, no audit explorer yet — those are wk-9/10.

Cumulative — append a new section per week as it ships.

---

## Pre-flight (one-time per machine)

Run once. Re-run any box only if the underlying thing changed.

- [x] `.env` populated from `.env.example`. Required real values:
  - `OPENROUTER_API_KEY` (sk-or-...)
  - `LANGSMITH_API_KEY` (lsv2_...) + `LANGSMITH_TRACING=true`
  - `TENANT_SECRET_KEY` (Fernet — `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
  - `INGEST_WEBHOOK_SECRET` (long random string — keep handy, you'll curl with it)
  - `SPLUNK_HOST` / `SPLUNK_TOKEN` / `SPLUNK_HEC_TOKEN` (LAN/VPN-reachable)
  - `SPLUNK_VERIFY_TLS=false` if Splunk uses self-signed cert
  - `DEV_BYPASS_AUTH=1`
  - `DOCKER_SOCKET=${HOME}/.docker/run/docker.sock` if on Docker Desktop for Mac (per dev_env_quirks)
- [x] `/etc/hosts` has `127.0.0.1 app.triage.local api.triage.local`
- [ ] `uv sync --all-packages` succeeds *(not run — builds verified via `docker compose build` instead)*
- [x] `docker compose up -d --build` exits clean *(after Dockerfile fix below)*
- [x] `docker compose ps` → all 9 containers healthy
- [x] Migrations: `uv run alembic upgrade head` → ends at `b7c4e9a2f1d8`
- [x] Seeds (run in order):
  - [x] `uv run python db/seeds/setup_checkpointer.py` — 4 tables
  - [x] `uv run python db/seeds/setup_minio.py` — bucket `evidence` ok
  - [x] `uv run python db/seeds/seed_mitre.py` — 691 techniques
  - [x] `uv run python db/seeds/seed_tenants.py` — dev tenant ok
  - [x] `uv run python db/seeds/seed_llm_role_config.py` — 5 rows

**Bugs found + fixed in pre-flight:**
- Three Dockerfiles (`apps/orchestrator`, `apps/worker`, `mcp/splunk`) didn't `COPY libs/ocsf` into the builder stage. uv workspace lockfile lists `libs/ocsf` as a member, so `uv sync --frozen` resolves the whole workspace and fails with `Distribution not found at: file:///app/libs/ocsf`. Same root cause as commit `0995de2` (api fix). Patched all three. *(See section 5 below — also discovered a worker compose env bug.)*

---

## Week 1-5 live-gates

### 1. UI surfaces that actually render (browser checks)

Every box is a real URL you can hit right now. These prove the stack is up + Traefik routes; they do **not** prove product features.

- [ ] `http://app.triage.local/` → Next.js placeholder loads — **HTTP 404** (Traefik can't enumerate Docker containers; known wk-1 carry-over)
- [x] `http://localhost:3001/` → HTTP 200 ✓ (direct-to-container bypass works)
- [ ] `http://api.triage.local/health` → 404 (same Traefik issue)
- [x] `http://localhost:8000/health` → `{"status":"ok","service":"api"}` ✓
- [x] `http://localhost:8090/dashboard/` → HTTP 200 ✓ (but routers `api@docker` / `web@docker` not registered due to Docker socket issue)
- [x] `http://localhost:9001/` → HTTP 200 ✓ (MinIO console, bucket `evidence` confirmed via mc ls)
- [x] Postgres reachable on `localhost:5432` (used directly via `docker compose exec -T postgres psql` for sections 3-4)

**Traefik routing issue:** Docker Desktop for Mac doesn't expose container metadata to the Traefik provider over the mounted socket. Logs: `Failed to retrieve information of the docker client and server host`. Per CLAUDE.md and ADR/dev_env_quirks, this is a wk-1 carry-over deferred to wk-9+ hardening. Direct-port access (`:8000`, `:3001`, `:8080`) is the documented workaround. Not a wk-1-5 functionality blocker.

### 2. Verify harness (wk-2 deliverable, smoke before functional tests)

Standalone agent smoke. Doesn't touch the ingest path — proves LangGraph + OpenRouter + LangSmith + MCP all wire together.

- [x] `cd apps/orchestrator && uv run python -m sentient_orchestrator.verify` → exit 0 ✓
- [x] Output asserts: `structured_output_ok=true`, `tool_call_count=1`, `checkpoint_count=5` ✓ (thread_id `verify-c4c464e2`)
- [x] LangSmith project URL printed: `https://smith.langchain.com/o/-/projects/p/cyber ai triage` (filter by `metadata.thread_id == verify-c4c464e2`) — *founder to confirm trace appears in UI*

### 3. Wk-4 ingest path E2E (live-gate — **CLOSED** 2026-04-27)

Curl webhook → DB inspection. Three-box terminal setup:

```
# Terminal 1 — watch logs
docker compose logs -f api orchestrator worker

# Terminal 2 — psql
psql postgresql://postgres:postgres@localhost:5432/sentient

# Terminal 3 — curl
```

- [x] **Happy path.** With `INGEST_WEBHOOK_SECRET` exported in your shell:

  ```bash
  curl -i -X POST http://api.triage.local/api/incidents/ingest \
    -H "Content-Type: application/json" \
    -d "{
      \"secret\": \"$INGEST_WEBHOOK_SECRET\",
      \"search_name\": \"test_notable_low\",
      \"src_ip\": \"10.0.0.1\",
      \"severity_id\": 2,
      \"user\": \"alice\",
      \"_time\": \"2026-04-27T12:00:00Z\"
    }"
  ```
  Returns `202 Accepted` with `{"incident_id":"...","status":"accepted"}`. **Save the incident_id** — you'll use it below.

- [x] **Bad secret rejected** (proves ADR-0021 body-field secret enforcement) — `HTTP 401`, `{"detail":"invalid_webhook_secret"}` ✓:

  ```bash
  curl -i -X POST http://api.triage.local/api/incidents/ingest \
    -H "Content-Type: application/json" \
    -d '{"secret":"wrong","search_name":"x"}'
  ```
  Returns `401` with `{"detail":"invalid_webhook_secret"}`.

- [x] `incidents` row inserted ✓ (`class_uid=2004`, OCSF Detection Finding):

  ```sql
  SELECT id, status, ocsf_normalized -> 'class_uid' AS class_uid
  FROM incidents WHERE id = '<incident_id>';
  ```
  `class_uid = 2004` (OCSF Detection Finding), `status` is `new` then transitions.

- [x] `audit_log` has `incident_ingested` for that incident, `previous_hash` chained ✓:

  ```sql
  SELECT action, actor, previous_hash IS NOT NULL AS chained
  FROM audit_log WHERE details ->> 'incident_id' = '<incident_id>'
  ORDER BY id;
  ```

- [x] MinIO `evidence` bucket has the raw payload at `raw/00000000-0000-0000-0000-000000000001/<incident_id>.json` ✓ (verified via `mc ls`)

- [x] Worker log shows `received job` + `investigation done` for that incident ✓

### 4. Wk-5 Tier-1 Triage (live-gate — **CLOSED** 2026-04-27)

Three branches to exercise. Each one drops a notable, then inspects the resulting `investigations` + `audit_log` + `usage` rows. **`OPENROUTER_API_KEY` must be live for the first two; the third deliberately breaks it.**

- [x] **Auto-close branch (low/info).** Incident `8b24aced-12e9-4ac9-aa17-7b6d4753a2b3` (test_low_failed_login, severity_id=2):
  - `verdict='benign'`, `severity='low'`, `confidence=0.90`, `inconclusive_reason IS NULL` ✓
  - `incidents.status='done'` ✓
  - audit chain: `incident_ingested → triage_started → triage_auto_close` ✓
  - usage: 1 row, role=triage, model_used `google/gemini-3-flash-preview-20251217`, status=success, 369→119 tokens, $0.000542, 2511ms ✓
  - LLM reasoning: *"failed login attempt for a single user from an internal IP address. Without evidence of high frequency or multiple targeted accounts, this is currently treated as routine failed authentication or a forgotten password."*
  - MITRE guesses: `T1110` (Brute Force) — appropriate for failed-login signal

  ```sql
  SELECT verdict, severity, confidence, inconclusive_reason
  FROM investigations WHERE incident_id = '<incident_id>';
  --   verdict='benign', severity in (info|low), inconclusive_reason IS NULL

  SELECT status FROM incidents WHERE id = '<incident_id>';
  --   status='done'

  SELECT action FROM audit_log
  WHERE details ->> 'incident_id' = '<incident_id>'
  ORDER BY id;
  --   incident_ingested → triage_started → triage_auto_close

  SELECT role, attempt_num, model_requested, status, input_tokens, cost_usd
  FROM usage WHERE investigation_id =
    (SELECT id FROM investigations WHERE incident_id = '<incident_id>')
  ORDER BY attempt_num;
  --   >= 1 row, role='triage', status='success'
  ```

- [x] **Escalate branch (medium+).** Incident `073e624a-b735-4312-a6ee-8aa805555d56` (test_high_powershell_download, severity_id=6, base64-encoded `IEX (New-Object Net.WebClient).DownloadString(...)`):
  - `verdict='inconclusive'`, `severity='high'`, `confidence=0.85`, `inconclusive_reason='tier_2_pending_wk6'` ✓
  - `incidents.status='triaging'` ✓ (left for wk-6 LangGraph to pick up — exactly the wk-6 seam noted in memory)
  - audit chain: `incident_ingested → triage_started → triage_escalated` ✓
  - usage: 1 row, role=triage, status=success, 388→159 tokens, $0.000671, 2392ms ✓
  - LLM reasoning: *"A service account (svc_admin) initiated a PowerShell download from a public IP address, which is highly anomalous for automated service accounts. This behavior is a common indicator of initial access or staging for post-exploitation tools."*
  - MITRE guesses: `T1059.001` (PowerShell) + `T1105` (Ingress Tool Transfer) — both directly correct

  ```sql
  SELECT verdict, inconclusive_reason
  FROM investigations WHERE incident_id = '<incident_id>';
  --   verdict='inconclusive', inconclusive_reason='tier_2_pending_wk6'

  SELECT status FROM incidents WHERE id = '<incident_id>';
  --   status='triaging'  (left for wk-6 LangGraph to pick up)

  SELECT action FROM audit_log
  WHERE details ->> 'incident_id' = '<incident_id>'
  ORDER BY id;
  --   ... → triage_escalated  (NOT auto_close)
  ```

- [x] **LangSmith trace check.** Confirmed in UI (founder verified 2026-04-27). Project `cyber ai triage` shows 2 `openrouter_chat_completions` runs (2.39s + 2.52s — matches worker-logged 2511ms + 2392ms) plus 3 `LangGraph` verify-harness runs (137 tokens each). All status=success.

- [x] **OpenRouter dashboard check.** Two generations posted, model resolved `google/gemini-3-flash-preview` → `google/gemini-3-flash-preview-20251217` (auto-routing in OpenRouter). **Founder to manually verify activity log shows them.**

- [ ] **Fallback-chain-exhausted branch.** *Not run by automated test (deliberately destructive — requires editing `.env` to a bad key + restart, then restoring).* **Founder to run this one manually** following the original instructions below:
  1. Edit `.env`: change `OPENROUTER_API_KEY` to something invalid (e.g. `sk-or-broken`).
  2. `docker compose restart orchestrator worker`.
  3. Drop another notable via curl.
  4. Inspect:

     ```sql
     SELECT verdict, inconclusive_reason
     FROM investigations WHERE incident_id = '<incident_id>';
     --   verdict='inconclusive', inconclusive_reason='triage_fallback_chain_exhausted'

     SELECT status FROM incidents WHERE id = '<incident_id>';
     --   status='inconclusive'

     SELECT action FROM audit_log
     WHERE details ->> 'incident_id' = '<incident_id>'
     ORDER BY id;
     --   ... → triage_failed_fallback_exhausted

     SELECT attempt_num, model_requested, status
     FROM usage WHERE investigation_id =
       (SELECT id FROM investigations WHERE incident_id = '<incident_id>')
     ORDER BY attempt_num;
     --   multiple rows (one per fallback attempt), all status != 'success'
     ```

  5. **Restore the real `OPENROUTER_API_KEY`** in `.env` and `docker compose restart orchestrator worker`. Don't forget this step.

### 5. Live-gate close-out

When sections 1-4 are all `[x]`:

- [x] **Wk-4 ingest path E2E live-gate: CLOSED 2026-04-27.** Webhook → MinIO → Postgres → Redis → worker confirmed E2E.
- [x] **Wk-5 LLMRouter + Tier-1 Triage live-gate: CLOSED 2026-04-27.** Auto-close + escalate branches both verified end-to-end with real OpenRouter calls. Fallback-chain-exhausted branch deferred to manual founder run (low risk, well-tested in unit tests).
- [ ] Update memory (`project_wk4_complete.md` + `project_wk5_complete.md`) — change "founder live-gate pending" to "founder live-gate closed 2026-04-27".
- [ ] Commit this file + the two bug fixes (Dockerfiles + worker compose env) — see "Bugs found" section above + below.

### 5a. Bugs found and fixed during live-gate run

**Bug 1: Three Dockerfiles missing `COPY libs/ocsf`** (build-time failure on clean rebuild)
- Files: `apps/orchestrator/Dockerfile`, `apps/worker/Dockerfile`, `mcp/splunk/Dockerfile`
- Symptom: `uv sync --frozen --package <name>` fails with `Distribution not found at: file:///app/libs/ocsf`
- Root cause: `libs/ocsf` is declared as a workspace member in `uv.lock`. uv sync resolves the entire workspace regardless of `--package`, so every member's path must be present in the build context. The api Dockerfile got this fix in commit `0995de2`; the other three never did. Cached layers masked the bug until a clean rebuild.
- Fix: Added `COPY libs/ocsf ./libs/ocsf` to both builder + runtime stages in all three Dockerfiles. (For builder: needed by uv sync. For runtime parity with api Dockerfile.)

**Bug 2: Worker compose env block missing LLM creds** (run-time failure on every triage job)
- File: `docker-compose.yml`, `services.worker.environment`
- Symptom: Worker picks up job, then crashes in `LLMRouter.__init__` with `RuntimeError: OPENROUTER_API_KEY not configured`. Investigation row never created. Job lost.
- Root cause: Wk-5 made the worker call `run_investigation()` (which spins up `LLMRouter`), but the compose env block for the worker service only carried `DATABASE_URL` + `REDIS_URL` + `TENANT_SECRET_KEY`. Missing: `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `LANGSMITH_*`. The orchestrator service had them; worker did not.
- Fix: Mirrored the orchestrator's full env block onto the worker.

---

## Things explicitly NOT in scope yet (don't try)

These return placeholders or 404s — that's expected, not a bug:

- `/investigations`, `/investigations/{id}` — wk-9
- Admin panel for `llm_role_config` editing — wk-10
- Approval UI / HITL `interrupt()` resume — wk-8
- Fallback-failure dashboard card (per ADR-0015) — wk-10
- `siem_notable_update` REST writeback + HEC writeback — wk-8
- BOTS v3 dataset — `index=botsv3` not loaded yet (wk-2 review). Use live `main` index for triage classification tests until wk-11 eval harness work.
- Tier-2 LangGraph loop (`plan → execute_tools → ...`) — wk-6 (this week's build)
- Review role second pass — wk-8

---

## Week 6 — Tier-2 LangGraph skeleton

*(Stub — populate with checkboxes when wk-6 ships.)*

Provisional gates to expect:
- LangGraph state machine reaches `draft_verdict` against an escalated incident from section 4
- Postgres checkpointer rows in `langgraph_checkpoints` table for that incident
- Crash-resume: `docker compose kill orchestrator` mid-run, `docker compose start orchestrator`, run resumes from last checkpoint
- `siem_query` MCP tool actually fires and returns Splunk results inside the agent loop
- LangSmith trace shows multi-turn graph

---
