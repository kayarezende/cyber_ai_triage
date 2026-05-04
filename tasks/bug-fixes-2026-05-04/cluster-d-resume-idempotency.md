# Cluster D — Resume + idempotency

**Estimated effort:** ≤2 days
**Touches:** orchestrator runner finalize path, HEC writeback, cli_resume + API approvals, await_approval audit emit, tools_node state
**Theme:** every node + every finalize must be idempotent under crash + double-resume. Wk-9 web UI + wk-12 reaper depend on this being right.

## Must read first
- `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py` — `_finalize_after_graph`, `resume_investigation`
- `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py` — `await_approval_node`, `tools_node`, `writeback_node`
- `apps/orchestrator/src/sentient_orchestrator/cli_resume.py`
- `apps/api/src/sentient_api/routers/approvals.py`
- `tasks/lessons.md` §Wk 8 — "Update incidents.status BEFORE interrupt() not after" + "Detect interrupt() via two independent signals"

## Findings to fix in this cluster

### CRIT-6 — Manifest re-upload on resume
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/runner.py:308-316` + `:618-689` (`_finalize_after_graph`)
- **Fix:**
  1. Atomic-finalize-claim: `UPDATE investigations SET completed_at = NOW() WHERE id = :id AND completed_at IS NULL RETURNING id` — if rowcount 0, short-circuit (someone else finalized).
  2. Move all post-graph side effects (manifest upload, writeback orchestration, completion audit emit) inside the claim. If claim returns no row → log + return.
  3. Special-case rejection path: rejection still needs to flip status; design so the claim happens BEFORE the writeback skip decision so a second resume on a rejected investigation also short-circuits.

### HIGH-9 — HEC not idempotent on resume
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:881-1022` (`writeback_node`) + `mcp/splunk/src/sentient_mcp_splunk/tools/siem_hec_post.py`
- **Fix:**
  1. `writeback_node`: read `investigations.writeback_status` BEFORE doing anything. If `'succeeded'` → log + return success without calling MCP.
  2. Add `sentient_dedup_id = f"{investigation_id}:{verdict_revision}"` to HEC payload. `verdict_revision` is a new column on `investigations` (default 1, incremented if the verdict text changes — for now always 1). Splunk-side dedup is deferred (founder-side index lookup); the field is for traceability + future wk-12 dedup.

### HIGH-13 — CLI resume bypasses dedup
- **Where:** `apps/orchestrator/src/sentient_orchestrator/cli_resume.py:105-130` vs `apps/api/src/sentient_api/routers/approvals.py:108-145`
- **Fix:**
  1. Move the `human_decision_submitted` audit insert + `EXISTS` dedup check INTO `runner.resume_investigation` itself.
  2. Both `cli_resume.py` and `approvals.py` then call `resume_investigation` and get the same dedup behavior.
  3. The dedup raises `ResumeAlreadySubmitted` (new exception); CLI prints + exits non-zero, API returns 409.

### HIGH-14 — `await_approval_node` audit not idempotent
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:704-749`
- **Fix:**
  1. The current SQL `UPDATE incidents SET status='awaiting_approval' WHERE id=:id AND status != 'awaiting_approval'` (or similar idempotent pattern). Capture rowcount.
  2. Only emit `awaiting_approval` audit if rowcount == 1 (real transition). On replay (rowcount 0), skip the audit emit.
  3. Same gate for `investigations.approval_status='pending'` flip.

### MED-5 — `tools_node` re-fires on resume → duplicate audit
- **Where:** `apps/orchestrator/src/sentient_orchestrator/investigation/nodes.py:285-369`
- **Fix:**
  1. Add `completed_tool_call_ids: set[str]` to `InvestigationState` (LangGraph StateGraph schema).
  2. In `tools_node`, before `await tool.ainvoke(args)`: `if tc["id"] in state.completed_tool_call_ids: skip + don't emit audit`.
  3. After successful invoke + audit emit: add `tc["id"]` to the set; LangGraph checkpoints the new state.

## Step-by-step fix order
1. HIGH-14 (small, isolated, sets pattern for "audit-on-real-transition only")
2. CRIT-6 (atomic finalize claim — hardest; everything else relies on this being clean)
3. HIGH-13 (move dedup into resume_investigation)
4. HIGH-9 (HEC idempotency check + dedup_id field)
5. MED-5 (tools_node skip-completed)

## Tests to add
- `apps/orchestrator/tests/investigation/test_finalize_atomic_claim.py` (NEW): two concurrent `_finalize_after_graph` calls → only one writes manifest + emits completion audit
- `apps/orchestrator/tests/investigation/test_writeback_idempotent.py` (NEW): `writeback_status='succeeded'` short-circuits second call; HEC payload contains `sentient_dedup_id`
- `apps/orchestrator/tests/investigation/test_resume_dedup.py` (NEW): two concurrent `resume_investigation` calls → second raises `ResumeAlreadySubmitted`; integration test covering both CLI + API entry points
- `apps/orchestrator/tests/investigation/test_await_approval_audit_idempotent.py` (NEW): replay `await_approval_node` 3 times → only 1 audit row
- `apps/orchestrator/tests/investigation/test_tools_node_skip_completed.py` (NEW): inject failure between tool calls + assert resumed run skips already-completed
- Extend `test_investigation_smoke.py` with crash-AFTER-manifest-upload scenario

## Verification before commit
- [ ] `uv run pytest` full suite green
- [ ] `ruff check && black --check && mypy --strict` clean
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` round-trip
- [ ] `python evals/run_eval.py --limit 1 --output /tmp/cluster-d-smoke.html` green
- [ ] Manual: drop a notable, let it reach `awaiting_approval`, run `cli_resume --approve` TWICE → second exits non-zero with ResumeAlreadySubmitted
- [ ] `tasks/lessons.md` entry: "Atomic finalize-claim via UPDATE … WHERE completed_at IS NULL RETURNING id is the only safe pattern for idempotent finalize"
- [ ] `tasks/lessons.md` entry: "Audit emits on state transitions must be gated on the rowcount of the UPDATE that drove the transition — replay safety"
- [ ] `tasks/lessons.md` entry: "Track completed work in LangGraph state, not derived from re-execution; idempotency keys ride in the state schema"

## Scope guard — DO NOT touch in this cluster
- DB roles, audit triggers (cluster A)
- HITL policy walker, severity ops (cluster B)
- LLM cap math (cluster C)
- Sanitizer limits (cluster E)
- Cross-process crash-resume reaper (wk-12 backlog per CLAUDE.md)

## Carry-forward (2026-05-04 close-out)
- **None of the spec is punted.** All 5 findings landed (CRIT-6 + HIGH-9 + HIGH-13 + HIGH-14 + MED-5).
- **Caveat captured in lessons.md** (not a deferral, a scope clarification): MED-5's `completed_tool_call_ids` only protects between-node crashes. Mid-`tools_node` worker death after a partial loop still re-fires the in-flight call until LangGraph checkpoints. This matches the spec scope ("between-node crashes + double-resume"); deeper protection (per-tool-call sub-graph or external dedup table) is wk-12 reaper territory.
- **Refactor during execution** (still in-spec): `claim_resume_intent` + `ResumeAlreadySubmitted` were extracted to `libs/common/src/sentient_common/resume.py` rather than living in `apps/orchestrator/.../investigation/runner.py`. Reason: the API container does not depend on the orchestrator package, so the original in-runner placement broke API container boot. Runner re-exports the symbols for backward compat. Lessons.md doesn't capture this — it's plumbing, not a generalizable rule.
