# Cluster E — Defence in depth

**Estimated effort:** ≤2 days
**Touches:** sanitizer, review-output persistence, audit emit failure path, several smaller MED items
**Theme:** these don't fail today on benign inputs but break under adversarial / pathological / degraded conditions. Last-line-of-defence fixes.

## Must read first
- `apps/orchestrator/src/sentient_orchestrator/investigation/sanitizer.py`
- `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py::_update_investigation_with_review`
- `apps/orchestrator/src/sentient_orchestrator/audit.py` — emit_* helpers
- `tasks/lessons.md` §Wk 8 — "Sensitive-field leaks travel through more than one channel"

## Findings to fix in this cluster

### HIGH-10 — `walk_and_sanitize` unbounded → DoS
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/sanitizer.py:57-72`
- **Fix:**
  1. Add module-level `_MAX_DEPTH = 64`, `_MAX_NODES = 10_000`.
  2. New private `_walk_with_limits(obj, depth, node_count) -> tuple[Any, int]` that threads depth + count through recursion.
  3. On overflow: replace subtree with the literal string `"[depth-exceeded]"` or `"[size-exceeded]"` (don't raise — sanitizer is on the hot path; truncation is safer than an exception that aborts the whole investigation).
  4. Public `walk_and_sanitize(obj)` calls `_walk_with_limits(obj, 0, 0)` and returns the result.
- **Test:** deep-nest input (1000 levels) → returns truncated marker; wide dict (1M keys) → returns truncated marker.

### HIGH-11 — Review notes/metadata stored unsanitized + uncapped
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py:601-615`
- **Fix:**
  1. `notes = sanitize_untrusted(str(review.get("notes") or ""))[:1024]`
  2. `metadata_clean = walk_and_sanitize(review)` (now bounded per HIGH-10 fix); persist `json.dumps(metadata_clean)` to `review_metadata`.
  3. Add SQL CHECK constraint via migration: `ALTER TABLE investigations ADD CONSTRAINT review_notes_len CHECK (review_notes IS NULL OR length(review_notes) <= 1024);`

### HIGH-12 — Audit emit failure swallowed silently
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:561-573, 585-597` + `runner.py:685-689`
- **Fix:**
  1. New table `audit_chain_gap` (migration): `id`, `investigation_id`, `tenant_id`, `attempted_action`, `error_message`, `created_at`. Plain table — no triggers, simple INSERT path.
  2. `audit.py`: new helper `emit_with_fallback(emit_fn, *args, fallback_action: str, **kwargs)` that wraps the emit call. On exception: log structured + INSERT `audit_chain_gap` row (best-effort; if THAT also fails, log and continue).
  3. Replace the bare `try/except: log.exception(...)` blocks in nodes.py + runner.py with `emit_with_fallback(...)`.
  4. Optional: surface `audit_chain_gap` count on the wk-11 admin usage dashboard later.

### MED-1 — Cap gate `>= 0 >= 0` (if not done in cluster C)
- If cluster C punted this, fix here.

### MED-3 — Resume `analyst_id` non-UUID lands in audit
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:762-768`
- **Fix:** in `await_approval_node` resume payload coercion, try `UUID(approver_id_raw)`; on ValueError → set to None + log warning. Don't pass raw string downstream.

### MED-4 — `mitre_techniques` from LLM unsanitized in audit
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:609-623`
- **Fix:** `InvestigationOutput.mitre_techniques` field validator: enforce `^T\d+(\.\d+)?$` regex per element. Pydantic v2 `Annotated[list[str], AfterValidator(validate_mitre_codes)]`. Drops malformed codes silently with a warning log.

### MED-7 — DSN missing fail-loud (if not done in cluster A)
- If cluster A punted this, fix here.

### MED-12 — `cached_tokens` parse safety
- **Where:** `apps/orchestrator/src/sentient_orchestrator/llm/openrouter.py:201-204`
- **Fix:** wrap in `try: cached = int(details.get("cached_tokens", 0) or 0); except (ValueError, TypeError): cached = 0`. Prevents a misbehaving provider from converting a successful HTTP call into a `validation_fail`.

### MED-14 — `approval_notes` SQL CHECK constraint
- **Fix:** add constraint in same migration as HIGH-11: `ALTER TABLE investigations ADD CONSTRAINT approval_notes_len CHECK (approval_notes IS NULL OR length(approval_notes) <= 1024);`

## Step-by-step fix order
1. New migration `g<hash>_defence_in_depth.py`: `audit_chain_gap` table + 2 CHECK constraints (HIGH-12 + HIGH-11 + MED-14)
2. HIGH-10 — sanitizer depth + node count limits (foundation for HIGH-11 metadata cleaning)
3. HIGH-11 — review notes + metadata sanitization
4. HIGH-12 — emit_with_fallback wrapper + replace bare try/except blocks
5. MED-1 / MED-7 — only if cluster C / A punted
6. MED-3 — analyst_id UUID coercion
7. MED-4 — InvestigationOutput mitre_techniques validator
8. MED-12 — cached_tokens parse safety

## Tests to add
- `apps/orchestrator/tests/investigation/test_sanitizer_limits.py` (NEW): deep-nest + wide-dict truncation
- `apps/orchestrator/tests/investigation/test_review_notes_sanitized.py` (NEW): review with control chars + 5KB notes → stored sanitized + truncated
- `apps/orchestrator/tests/investigation/test_audit_emit_fallback.py` (NEW): mock emit_review_skipped to raise → assert audit_chain_gap row inserted
- `apps/orchestrator/tests/investigation/test_analyst_id_uuid_coercion.py` (NEW): non-UUID resume payload → audit has None, log warning
- `apps/orchestrator/tests/investigation/test_mitre_validator.py` (NEW): malformed T-code dropped
- `apps/orchestrator/tests/llm/test_cached_tokens_parse_safety.py` (NEW): non-numeric `cached_tokens` doesn't crash response parse

## Verification before commit
- [ ] `uv run pytest` full suite green
- [ ] `ruff check && black --check && mypy --strict` clean
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` round-trip
- [ ] `python evals/run_eval.py --limit 1 --output /tmp/cluster-e-smoke.html` green
- [ ] `tasks/lessons.md` entry: "Recursive sanitizers must have depth + node-count caps; truncate-with-marker beats raise on the hot path"
- [ ] `tasks/lessons.md` entry: "Audit emit failures must surface — silent swallow is worse than the underlying bug because verify_chain validates the partial chain as intact"
- [ ] `tasks/lessons.md` entry: "LLM-generated fields that flow into audit / DB / UI must be Pydantic-validated at the source, not at every consumer"

## Scope guard — DO NOT touch in this cluster
- DB roles, audit hash trigger, thread_id (cluster A)
- HITL policy walker, Tier-1 sanitizer (cluster B)
- LLM cap math (cluster C)
- Resume / finalize idempotency (cluster D)
- Wk-12 backlog items: per-tenant Splunk client refactor, hard tenancy, Vault/KMS, IRAP

## Carry-forward
(Fill in if anything punted.)
