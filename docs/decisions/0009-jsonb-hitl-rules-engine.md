# 0009: JSONB-based HITL rules engine

Date: 2026-04-15
Status: Accepted

## Context

The product must support human-in-loop (HITL) review of agent verdicts. Founder wants maximal control over when the AI interrupts for human review:
- MVP (training phase): human approves 100% of verdicts. Founder reviews everything to bootstrap trust + eval data.
- Post-MVP: per-tenant thresholds. Options considered were (a) confidence-only, (b) severity-only, (c) combined boolean expressions. Founder wants all three supported eventually.

Schema options:
- Hard-coded columns per knob (`hitl_min_confidence`, `hitl_severity_threshold`, ...). Migrations on every new knob.
- Single JSONB `rule_expression` per policy. No migrations when rules evolve.

## Decision

**JSONB-based rule expression tree per tenant, evaluated by a simple Python tree walker.**

Schema:
```sql
CREATE TABLE hitl_policies (
  id UUID PRIMARY KEY,
  tenant_id UUID,
  name TEXT,
  rule_expression JSONB,
  priority INT,        -- lower = first match wins
  enabled BOOLEAN
);
```

Expression tree:
- Leaf: `{"field": "severity", "op": "eq", "value": "critical"}`
- Branch: `{"op": "AND|OR", "conditions": [...]}`
- Short-circuit: `{"op": "always_true"}` (MVP default).

MVP default policy: `{"op": "always_true"}` → 100% human approval.
MVP implementation: ~50-line evaluator walks the tree, returns `True` (human needed) or `False` (auto-approve). Admin panel exposes raw JSON textbox.
Post-MVP: drag-and-drop rule builder UI. Same schema backend.

Graph-level mechanism: LangGraph `interrupt()` node (`await_approval`) pauses the investigation; state persists in `PostgresSaver` checkpointer; analyst resumes via UI.

## Alternatives considered

- **Hard-coded columns** — each new knob requires an Alembic migration. Rejected for rule-design velocity.
- **Rego / OPA policies** — battle-tested policy engine, but adds OPA as a dep + Rego as a DSL for every user. Rejected as overkill for MVP.
- **Arbitrary Python expressions stored as strings** — would execute user-supplied code at evaluation time, which is an unacceptable RCE surface. Rejected on security grounds.
- **Simple thresholds in YAML** — rejected because combined AND/OR semantics would require re-inventing a mini-DSL anyway. JSONB + tree walker is the simpler expression.

## Consequences

**Gain:**
- Schema is stable as rule semantics evolve — no migrations when we add new `field`s (e.g., "mitre_contains_any").
- MVP implementation is trivial (~50 lines) with no code execution — operations are an allowlisted set (`eq`, `in`, `lt`, `gt`, `AND`, `OR`, etc.).
- Same backend serves future drag-and-drop builder.
- Rule expressions are inspectable/diffable as JSON — good for audit trail.

**Accept:**
- JSONB loses SQL-level queryability of individual conditions (can't easily `WHERE severity_threshold > X`).
- No static analysis of rules — you can write a rule that always evaluates to False (auto-approve everything). Add a validator in the admin panel that warns on suspicious rule shapes.
- MVP admin UI is a raw JSON textbox — not user-friendly for non-technical admins. Mitigation: post-MVP builder.

## Related

- ADR 0003 — LangGraph `interrupt()` is the mechanism that consumes this rule output.
- `docs/context/stack-locks.md` — HITL lock.
