# 0006: Soft multi-tenancy via Postgres RLS

Date: 2026-04-15
Status: Accepted

## Context

MVP has one tenant (founder) but the architecture needs to support multi-tenant from day 1 because:
- Cloud-hosted MSSP customers will have multiple sub-tenants.
- Audit log + usage billing are already per-tenant concepts.
- Changing tenancy model later is expensive.

Two models:
- **Soft multi-tenancy** — shared DB, `tenant_id` column on every table, Postgres Row-Level Security (RLS) enforces isolation.
- **Hard multi-tenancy** — separate Postgres schemas or separate databases per tenant, separate KMS keys, per-tenant MCP server containers.

## Decision

**Soft multi-tenancy for MVP.** Single Postgres, `tenant_id` column on every tenant-scoped table, RLS policies enforce isolation, application sets `app.current_tenant` session variable per request.

Hard tenancy deferred to month 6+ or when a customer requires it (IRAP, regulated sector).

## Alternatives considered

- **Hard multi-tenancy from day 1** — 4-6 weeks of extra work (schema-per-tenant migrations, per-tenant MCP containers, per-tenant KMS keys). Kills MVP timeline. No customer is paying for it yet.
- **No multi-tenancy (single-tenant-only)** — would need significant refactor to add later. Audit log and usage tables are already natural per-tenant.

## Consequences

**Gain:**
- Single schema + single DB = simple migrations, simple backups.
- Foundation for multi-tenant billing + audit — trivial to add a tenant.
- RLS enforces isolation at DB layer as defense-in-depth.

**Accept:**
- Trust boundary = application sets `app.current_tenant` correctly + RLS. Bug in the app layer could cross-contaminate tenants.
- Not acceptable for IRAP/high-sensitivity customers. Must harden before serving those.
- Performance: queries on very-large tenant data can share noisy-neighbor effect. Monitor.

## Related

- ADR 0011 — auth model (populates `app.current_tenant` per request).
- `docs/context/stack-locks.md` — multi-tenancy lock.
