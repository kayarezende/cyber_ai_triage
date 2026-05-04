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

**CLOSED.** No carry-forward to cluster B.

### Cold-start migration gate (compose sidecar) — DONE at a1d6e31
Originally punted; shipped as a follow-up. New `migrate` one-shot service runs `alembic upgrade head` then exits. Reuses the api image (alembic + db/migrations baked in via Dockerfile + `alembic>=1.13` added to `apps/api/pyproject.toml`). Idempotent — sub-second no-op when DB is already at head.

### Hands-free seed sidecar — DONE at 3baad14
Bonus follow-up. New `seed` one-shot service chains after migrate and runs all 7 seeds in dependency order (setup_checkpointer → setup_minio → seed_tenants → seed_mitre → seed_llm_role_config → seed_hitl_policies → seed_detection_rules) via `db/seeds/seed_all.py`. All idempotent. seed_mitre fast-paths skip the 50 MB STIX download when the table is already populated. New `.dockerignore` keeps the cache out of the build context. api/orchestrator/worker now `depends_on: seed: service_completed_successfully` (transitively waits on migrate). Cold-start (`docker compose down -v && up -d`) is now hands-free in ~30s.

### Live-gate CLOSED (verified 2026-05-04)
All gate steps pass:
- `alembic downgrade -1 && alembic upgrade head` round-trip ✓
- `docker compose down -v && docker compose up -d` cold-start ✓ (now hands-free via migrate + seed sidecars; no manual alembic / seed steps needed)
- `python evals/run_eval.py --limit 1 --output /tmp/cluster-a-smoke.html` live canary ✓ (worker logs show new thread_id format `00000…0001:1bd0…b22` and graph reaches `tier-2 interrupted at await_approval; pending analyst` — the eval timeout is the HITL pause from the default 100% human approval policy, not a regression)
- `apps/api/tests/test_app_runtime_role.py` + `apps/orchestrator/tests/test_audit_chain_concurrency.py` — 7/7 integration tests pass against live Postgres

Two migration bugs surfaced + fixed in-session (committed as a follow-up to 8c12576):
1. DO-block + parameter binding combo failed under psycopg (`IndeterminateDatatype`). Fixed by doing the role existence check in Python + emitting plain `CREATE ROLE`/`ALTER ROLE` with SQL-escaped password.
2. `ALTER DEFAULT PRIVILEGES` only covers future tables. The 4 LangGraph checkpointer tables created by `setup_checkpointer.py` are out-of-band — they exist by the time the role is granted, so default privs miss them. Fixed by also doing `GRANT … ON ALL TABLES IN SCHEMA public` for existing tables, then re-restricting `audit_log` to INSERT+SELECT only.

Pre-existing flake exposed (not cluster A): `apps/orchestrator/tests/test_verify_smoke.py::test_verify_smoke_resumes_after_inject_failure` fails with `APIConnectionError` when run after `test_verify_smoke_completes` (passes in isolation). OpenRouter connection-pool/rate-limit issue between back-to-back tests, unrelated to cluster A's role/grant changes. Track for cluster D test isolation work.

### Simplifications vs original cluster file
- `_load_resume_context` reads `langgraph_thread_id` from the DB column rather than reconstructing from `investigation_id`. The original plan called for a "legacy parser" so old `inv-XXXX` thread_ids could still be parsed; in practice no parser is needed because the DB column is the source of truth. In-flight investigations finalize naturally.
- `audit_writer` role kept INHERIT (default) rather than the cluster file's literal NOINHERIT, so the membership grant is load-bearing rather than ceremonial. Direct INSERT grant on `audit_log` is also kept for explicitness.
- `audit_log` only receives INSERT + SELECT for app_runtime (not the full DML the cluster file suggested). UPDATE/DELETE attempts now fail at privilege check before the append-only triggers fire — defence-in-depth.
