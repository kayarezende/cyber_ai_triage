# Bug fixes — 2026-05-04 review

Triggered by the 2026-05-04 multi-agent codebase review (3 parallel general-purpose agents over LLM router, HITL/writeback, sanitizer + audit + checkpointer). Findings: 6 critical, 14 high, 13 medium, 5 low.

## How to use this folder
- One cluster per Claude Code session. Wipe session between clusters.
- Each cluster file is self-contained — start a fresh session, point Claude at the file, execute.
- After each cluster: run the **cross-cluster verification gate** (below) before starting the next.
- Findings IDs (CRIT-1, HIGH-1 etc) match the review report. Cross-cluster files reference each other by ID.

## Cluster order (recommended)
| # | File | Theme | Est | Why this slot |
|---|------|-------|-----|---------------|
| A | `cluster-a-compliance.md` | Multi-tenant + audit integrity | ≤3d | Highest leverage; AU MSSP positioning depends on it |
| B | `cluster-b-silent-failures.md` | Wrong verdict shipped | ≤1d | Highest risk-of-quiet-prod-failure |
| C | `cluster-c-cost-cap.md` | Cap evasion | ≤1d | Money + ADR-0015 audit ledger contract |
| D | `cluster-d-resume-idempotency.md` | Crash + double-resume safety | ≤2d | Blocks reliable HITL flows + wk-9 web UI |
| E | `cluster-e-defence-in-depth.md` | Sanitizer + ledger gap visibility | ≤2d | Last-resort defences; some MED items folded in |

Total: ~8-9 days. Cluster A and D can pair with their own commit each because both touch DB schema. B + C are pure-Python and could pair if appetite is high.

## Cross-cluster verification gate (run between every cluster)
Before starting cluster N+1, the just-finished cluster N must satisfy:

- [ ] Full pytest suite green: `uv run pytest`
- [ ] `ruff check` + `black --check` + `mypy --strict` clean across changed files
- [ ] Migration round-trip (if cluster touched DB): `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
- [ ] Live canary green: `python evals/run_eval.py --limit 1 --output /tmp/cluster-N-smoke.html` against the local compose stack (per `tasks/lessons.md` §Wk 10 §"Live eval-harness smoke caught two prod bugs")
- [ ] `tasks/lessons.md` updated with any generalizable lesson from this cluster (rule + reason + how to apply)
- [ ] Commit pushed (or staged + reviewed by founder) with message `feat(bugfix-cluster-N): <theme>`
- [ ] No carry-over: every finding ID listed in the cluster file is either fixed OR explicitly punted with a one-line note in the cluster file's "Carry-forward" section

If any box doesn't tick: do not start the next cluster. Either fix or punt explicitly.

## Reading order for a fresh session
1. Project `CLAUDE.md` (root)
2. `tasks/lessons.md` — last 5 entries
3. The cluster file you are starting
4. Any file the cluster file flags as "must read first"

Do not read the other cluster files unless cross-referenced. Each cluster is independent.

## Findings catalog (linked to cluster files)
- CRIT-1 superuser bypass → cluster A
- CRIT-2 audit_log TRUNCATE → cluster A
- CRIT-3 Tier-1 sanitizer bypass → cluster B (paired with sanitizer awareness, but lives with HITL silent-failure fixes since it is a single-file change)
- CRIT-4 audit hash chain race → cluster A
- CRIT-5 schema-retry uncosted → cluster C
- CRIT-6 manifest re-upload on resume → cluster D
- HIGH-1 severity gte broken → cluster B
- HIGH-2 writeback_mode silent downgrade → cluster B
- HIGH-3 notable_update success-on-error → cluster B
- HIGH-4 policy walker uncaught → cluster B
- HIGH-5 thread_id missing tenant_id → cluster A
- HIGH-6 cap gate per attempt → cluster C
- HIGH-7 cap gate concurrency → cluster C
- HIGH-8 NUMERIC(10,6) overflow → cluster C
- HIGH-9 HEC dedup → cluster D
- HIGH-10 sanitizer unbounded recursion → cluster E
- HIGH-11 review notes unsanitized → cluster E
- HIGH-12 audit emit silent swallow → cluster E
- HIGH-13 CLI resume bypass dedup → cluster D
- HIGH-14 await_approval audit dedup → cluster D
- MED-1..14 + LOW-1..5 → cluster E (selected) or wk-12 backlog
