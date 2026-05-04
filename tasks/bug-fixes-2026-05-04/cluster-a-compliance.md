# Cluster A — Compliance / multi-tenant integrity

**Estimated effort:** ≤3 days
**Touches:** DB roles, RLS plumbing, audit-log triggers, LangGraph thread-id construction
**Theme:** make the on-paper compliance posture (ADR-0017, soft multi-tenancy, audit chain integrity) actually load-bearing in code.

## Must read first
- `docs/decisions/0017-*.md` — audit-writer + hash-chain ADR
- `db/migrations/versions/b7c4e9a2f1d8_*.py` — current trigger + role definitions
- `libs/common/src/sentient_common/db.py` — `tenant_session` + RLS context manager
- `tasks/lessons.md` §Wk 8 — "FK violation rolls back finalize txn" + "Sensitive-field leaks travel through more than one channel"

## Findings to fix in this cluster

### CRIT-1 — App connects as Postgres superuser
- **Where:** `libs/common/src/sentient_common/db.py:30-34` + `docker-compose.yml` + `.env.example`
- **Why bad:** Superuser bypasses RLS on every tenant table; UPDATE/DELETE/TRUNCATE on `audit_log` work despite triggers. ADR-0017 protections exist on paper only.
- **Fix:**
  1. New migration `e<hash>_app_runtime_role.py`:
     - `CREATE ROLE app_runtime LOGIN PASSWORD :pw NOINHERIT;` (password from migration env)
     - `GRANT CONNECT ON DATABASE sentient TO app_runtime;`
     - `GRANT USAGE ON SCHEMA public TO app_runtime;`
     - For each tenant-scoped table: `GRANT SELECT, INSERT, UPDATE, DELETE ON <t> TO app_runtime;` then re-apply RLS policies (RLS bypass requires `BYPASSRLS` attribute, which app_runtime does NOT have)
     - `GRANT INSERT, SELECT ON audit_log TO audit_writer;` (already exists; verify)
     - `GRANT audit_writer TO app_runtime;` so role inheritance works
     - For sequences: `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;`
  2. `libs/common/src/sentient_common/db.py`:
     - Inside `tenant_session`, after `SET LOCAL app.current_tenant`, add `SET LOCAL ROLE app_runtime;`
     - Also: raise loud at first `tenant_session()` call if `DATABASE_URL` env unset (don't fall back to `postgres:postgres@localhost`)
  3. `docker-compose.yml` + `.env.example`: switch `DATABASE_URL` to use `app_runtime` user. Keep `postgres` user available for migrations only (alembic.ini stays superuser).
  4. Carve out: alembic migrations run as superuser (separate DSN, e.g. `MIGRATION_DATABASE_URL`). Document in README.

### CRIT-2 — TRUNCATE on audit_log not blocked
- **Where:** migration `b7c4e9a2f1d8:135-148`
- **Fix:** add to the same new migration as CRIT-1:
  ```sql
  CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION block_audit_modify();
  ```

### CRIT-4 — Audit hash chain race
- **Where:** trigger `compute_audit_hash` in migration `b7c4e9a2f1d8:90-117`
- **Fix:** modify trigger function (in the new migration as a CREATE OR REPLACE FUNCTION):
  - At the top, before the `SELECT prev_hash`, add: `PERFORM pg_advisory_xact_lock(hashtext('audit_log:' || COALESCE(NEW.hash_scope, '')));`
  - Lock is released at txn commit, so within-txn inserts to the same scope serialize.

### MED-6 — Hash digest doesn't bind hash_scope
- **Where:** trigger `compute_audit_hash` (same as CRIT-4) + `libs/common/src/sentient_common/audit.py::compute_audit_row_hash`
- **Fix:** prepend `COALESCE(NEW.hash_scope, '') || '|' ||` in both the plpgsql digest concat AND the Python helper. They MUST stay in lockstep — add a comment cross-referencing in both places.

### HIGH-5 — LangGraph thread_id omits tenant_id
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py:72-73`
- **Fix:**
  1. `_make_thread_id(tenant_id, investigation_id) -> f"{tenant_id.hex}:{investigation_id.hex}"`
  2. `_load_resume_context` parses both new and legacy shape (legacy = `inv-<12hex>`) so existing in-flight investigations don't strand. Fall back: legacy threads keep working until they finalize; new threads use new shape.
  3. Update tests in `apps/orchestrator/tests/test_investigation_smoke.py` to round-trip the new shape.
  4. NO data migration on existing rows — they finalize naturally; new investigations use new shape.

## Step-by-step fix order
1. Write migration `e<hash>_app_runtime_role.py` (CRIT-1 + CRIT-2 + CRIT-4 + MED-6 in one migration since they share trigger function)
2. Update `libs/common/src/sentient_common/db.py` (CRIT-1 SET LOCAL ROLE + DSN-required guard)
3. Update `libs/common/src/sentient_common/audit.py` (MED-6 lockstep digest change)
4. Update `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py` (HIGH-5 thread_id + resume parser)
5. Switch docker-compose + .env.example DSN to `app_runtime`
6. Carve `MIGRATION_DATABASE_URL` for alembic; update alembic env.py to read it; document in README
7. Run integration tests (below)
8. Manual: `docker compose down -v && docker compose up -d` to confirm cold-start works with new role
9. Run live eval canary

## Tests to add
- `apps/api/tests/integration/test_app_runtime_role.py` (NEW):
  - cross-tenant SELECT denied (open `tenant_session(tenant_a)`, attempt SELECT on incident owned by tenant_b → 0 rows)
  - `TRUNCATE audit_log` denied (raises permission denied)
  - `UPDATE audit_log SET action='x' WHERE id=:id` denied
  - `DELETE FROM audit_log WHERE id=:id` denied
  - audit `INSERT` works
- `apps/orchestrator/tests/integration/test_audit_chain_concurrency.py` (NEW):
  - 5 concurrent `INSERT INTO audit_log` rows into the same `hash_scope` via asyncio.gather → `verify_chain` accepts result, no fork
  - cross-scope row-substitution detected: insert row from scope A into scope B with same content → verify_chain rejects (this is the MED-6 protection)
- `apps/orchestrator/tests/test_thread_id.py` (NEW):
  - `_make_thread_id` includes tenant_id hex prefix
  - `_load_resume_context` accepts both new and legacy shape

## Verification before commit
- [ ] `uv run pytest` full suite green
- [ ] `ruff check && black --check && mypy --strict` clean
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` round-trip
- [ ] `docker compose down -v && docker compose up -d` cold-start green
- [ ] `python evals/run_eval.py --limit 1 --output /tmp/cluster-a-smoke.html` green
- [ ] `tasks/lessons.md` entry: "Provision app_runtime role for RLS to actually apply — superuser bypasses RLS regardless"
- [ ] `tasks/lessons.md` entry: "TRUNCATE needs its own trigger; BEFORE DELETE doesn't cover it"
- [ ] `tasks/lessons.md` entry: "Hash chain triggers need pg_advisory_xact_lock to handle concurrent inserts"

## Scope guard — DO NOT touch in this cluster
- LLM router, usage, cost cap (cluster C)
- HITL policy walker, writeback nodes (clusters B + D)
- Sanitizer recursion limits (cluster E)
- Any wk-12 hard-tenancy / Vault refactor — not in MVP scope per CLAUDE.md

## Carry-forward

### Cold-start migration gate (compose sidecar)
Compose currently has no `service_completed_successfully` gate from app services to a migration runner. With cluster A switching the app DSN to `app_runtime`, a cold `docker compose down -v && up` will fail to authenticate until `alembic upgrade head` runs (the role doesn't exist until then). Workaround: founder runs `alembic upgrade head` before bringing app services up. Follow-up commit will add a `migrate` one-shot service to compose with `depends_on: { migrate: { condition: service_completed_successfully } }` on api/orchestrator/worker.

### Live-gate pending (no Docker in this session)
Three verification steps from this cluster's gate could not run because Docker Desktop wasn't running in the implementation environment:
- `alembic downgrade -1 && alembic upgrade head` round-trip
- `docker compose down -v && docker compose up -d` cold-start
- `python evals/run_eval.py --limit 1 --output /tmp/cluster-a-smoke.html` live canary
- The two new integration tests (`apps/api/tests/test_app_runtime_role.py` + `apps/orchestrator/tests/test_audit_chain_concurrency.py`) — they `pytest.skip` without `MIGRATION_DATABASE_URL` + `APP_RUNTIME_PASSWORD` set against a live Postgres.

Founder must run these on the dev box before declaring cluster A shipped. They join the existing wk-6/7/8/9/10 live-gate backlog.

### Simplifications vs original cluster file
- `_load_resume_context` reads `langgraph_thread_id` from the DB column rather than reconstructing from `investigation_id`. The original plan called for a "legacy parser" so old `inv-XXXX` thread_ids could still be parsed; in practice no parser is needed because the DB column is the source of truth. In-flight investigations finalize naturally.
- `audit_writer` role kept INHERIT (default) rather than the cluster file's literal NOINHERIT, so the membership grant is load-bearing rather than ceremonial. Direct INSERT grant on `audit_log` is also kept for explicitness.
- `audit_log` only receives INSERT + SELECT for app_runtime (not the full DML the cluster file suggested). UPDATE/DELETE attempts now fail at privilege check before the append-only triggers fire — defence-in-depth.
