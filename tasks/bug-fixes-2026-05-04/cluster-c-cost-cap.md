# Cluster C — Cost cap evasion

**Estimated effort:** ≤1 day
**Touches:** LLM router, usage logging, OpenRouter response parser, one DB column widen
**Theme:** the per-investigation cost cap can be evaded through the schema-retry path and through concurrent calls. Closes ADR-0015 ledger contract.

## Must read first
- `docs/decisions/0015-*.md` — app-side fallback ledger ADR
- `apps/orchestrator/src/sentient_orchestrator/llm/router.py` — fallback loop + budget check
- `apps/orchestrator/src/sentient_orchestrator/llm/usage.py` — usage logger
- `apps/orchestrator/src/sentient_orchestrator/llm/openrouter.py` — response parser
- `db/migrations/versions/c1d8e3f4a9b2_*.py` — wk-7 cost-cap migration
- `tasks/lessons.md` §Wk 7 — "Defend cost-accumulator UPDATEs against Byzantine inputs at SQL time"

## Findings to fix in this cluster

### CRIT-5 — Schema-retry HTTP call uncosted + unaccumulated
- **Where:** `apps/orchestrator/src/sentient_orchestrator/llm/router.py:372-395` (`_validate_with_retry`)
- **Fix:** inside `_validate_with_retry`, after the second `_traced_call` returns:
  1. `log_usage_attempt(self._conn, attempt_num=attempt_num, retry_seq=1, model_requested=model, status='success'|'validation_fail', ..., latency_ms=...)`
  2. `update_investigation_totals(self._conn, retry_response.input_tokens, retry_response.output_tokens, retry_response.cost_usd)`
  3. New column on `usage`: `retry_seq INT NOT NULL DEFAULT 0` (0 = primary attempt, 1 = first schema-retry, etc). Migration adds it.
  4. Update `update_investigation_totals` callers + tests for the new column.
- **Note:** this single fix closes M4 + M5 + M9 of the LLM-review report by design — same shape, same hole.

### HIGH-6 — Cap gate per attempt
- **Where:** `apps/orchestrator/src/sentient_orchestrator/llm/router.py:139-175` (the for-loop over fallback chain)
- **Fix:** at top of each loop iteration when `attempt_num > 1`, call `self._check_budget(...)` again. Cheap (single SELECT). Use the same connection so it sees the just-written failure totals from the prior iteration.

### HIGH-7 — Cap gate concurrency
- **Where:** `apps/orchestrator/src/sentient_orchestrator/llm/router.py:399-409` (`_check_budget`)
- **Fix:** change `_check_budget` query to `SELECT ... FOR UPDATE OF investigations` so two concurrent calls on same investigation serialize on the row lock. Add docstring note: lock holds for the txn duration; callers that hold tenant_session for many calls should consider scope.

### HIGH-8 — NUMERIC(10,6) overflow
- **Where:** migration `81e2d43b3ec0:155` + `apps/orchestrator/src/sentient_orchestrator/llm/openrouter.py:205-206` + binding sites in usage.py + router.py
- **Fix:**
  1. New migration `f<hash>_widen_cost_columns.py`:
     - `ALTER TABLE investigations ALTER COLUMN total_cost_usd TYPE NUMERIC(14,6);`
     - `ALTER TABLE usage ALTER COLUMN cost_usd TYPE NUMERIC(14,6);`
     - `ALTER TABLE tenants ALTER COLUMN per_investigation_budget_usd TYPE NUMERIC(14,6);`
  2. `openrouter.py`: change `cost_usd: float` parsing to `cost_usd: Decimal | None`. Use `Decimal(str(raw))` to avoid binary-float drift.
  3. usage.py + router.py bind sites: pass `Decimal` not `float` to SQLAlchemy params.
  4. evidence.py manifest: keep `float()` for JSON serialization but source from `investigations.total_cost_usd` (the SoT) per LOW finding.
- **Test:** insert a $1000 investigation cost → no overflow.

### MED-1 — `>= 0 >= 0` evaluates True
- **Where:** `apps/orchestrator/src/sentient_orchestrator/llm/router.py:415-418`
- **Fix:** document `cap_usd == 0` semantically:
  - Recommendation: `cap_usd == 0` means "disabled" → short-circuit `_check_budget` returns early without raising.
  - Alternative: change to strict `>` so $0 cost on $0 cap doesn't raise.
  - Pick the disabled semantic; it matches the pattern used elsewhere in the project where 0 means "no limit." Document in tenant.per_investigation_budget_usd column comment.

## Step-by-step fix order
1. New migration `f<hash>_widen_cost_columns.py` (HIGH-8 + adds `retry_seq` for CRIT-5)
2. CRIT-5 — log + accumulate retry call + new retry_seq column passed in
3. HIGH-6 — move `_check_budget` inside loop
4. HIGH-7 — `FOR UPDATE` on investigations row in `_check_budget`
5. MED-1 — `cap_usd == 0` short-circuit
6. Update OpenRouter parser to use Decimal end-to-end
7. Update tests

## Tests to add
- `apps/orchestrator/tests/llm/test_validate_with_retry_logs_usage.py` (NEW)
- `apps/orchestrator/tests/llm/test_cap_gate_per_attempt.py` (NEW)
- `apps/orchestrator/tests/llm/test_cap_gate_concurrency.py` (NEW — uses asyncio.gather + assert serialized)
- `apps/orchestrator/tests/llm/test_decimal_no_overflow.py` (NEW — $1000 cost insert)
- `apps/orchestrator/tests/llm/test_cap_zero_disabled.py` (NEW — cap=0 doesn't raise on cost=0)
- Existing `test_budget_cap_pre_call_usd_exceeded_raises` updated for Decimal types

## Verification before commit
- [ ] `uv run pytest` full suite green
- [ ] `ruff check && black --check && mypy --strict` clean
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` round-trip
- [ ] `python evals/run_eval.py --limit 1 --output /tmp/cluster-c-smoke.html` green
- [ ] `tasks/lessons.md` entry: "Every LLM HTTP call must log a usage row + accumulate totals — including schema-retry calls; one retry hidden = cap evadable indefinitely"
- [ ] `tasks/lessons.md` entry: "Cap gates must re-check between fallback attempts AND lock the row to defend against concurrent calls on same investigation"
- [ ] `tasks/lessons.md` entry: "Float→Decimal at the boundary; never bind float to NUMERIC columns"

## Scope guard — DO NOT touch in this cluster
- DB roles, audit (cluster A)
- HITL or sanitizer (clusters B + E)
- Resume / finalize (cluster D)
- LangSmith tracing config (MED-8 — wk-12 backlog)

## Carry-forward

(none) — closed 2026-05-04. All 5 findings (CRIT-5, HIGH-6, HIGH-7, HIGH-8, MED-1) shipped in a single commit. Migration `f2c8b6e1d34a` widens cost columns + adds `usage.retry_seq`. ADR-0015 amended with "Retry semantics" subsection. Wk-7 lesson at `tasks/lessons.md` schema-retry-uncosted entry marked CLOSED in-place. New cluster-C lessons appended (4 rules). Live canary green; integration tests for FOR UPDATE serialisation + $1000 cost overflow + Decimal precision round-trip pass against the live compose Postgres. 648 unit tests + 4 cluster-C integration tests green.
