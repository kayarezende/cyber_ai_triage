# 0011: Dev-bypass auth for MVP, Entra SSO in wk 11

Date: 2026-04-15
Status: Accepted

## Context

External AU mid-market/MSSP customers will require Entra ID (Microsoft Entra, formerly Azure AD) SSO for their analysts. Entra OIDC integration takes 2-3 days of OIDC plumbing + testing. During MVP scaffolding (wk 1-8), the only user is the founder on a local environment.

Front-loading Entra in wk 1 burns early momentum on zero-external-value work.

## Decision

**Dev-bypass auth for MVP (wk 1-10).** Env flag `DEV_BYPASS_AUTH=1` plus a simple email sign-in that auto-creates a user. No passwords, no OIDC.

**Entra ID SSO implemented in wk 11** — pre-demo hardening. FastAPI OIDC middleware on the API side; Next.js middleware on the frontend. Dev bypass remains behind the env flag for local dev.

Middleware populates `app.current_tenant` Postgres session variable per request (see ADR 0006).

## Alternatives considered

- **Entra from wk 1** — 2-3 days burned before shipping value to the only user (founder). Rejected.
- **Email + password (bcrypt) as MVP** — stops being "simpler than Entra" once you implement password reset, lockout, rate limits. More code than dev-bypass. Rejected.
- **Magic link email** — still needs an email provider + template. Rejected as over-investment.
- **Skip auth entirely** — production-unsafe, confusing, requires invasive retrofit later. Rejected.

## Consequences

**Gain:**
- ~3 days saved in wk 1.
- Local dev remains frictionless throughout MVP build.
- Entra implemented with full context of the app's auth needs (users, tenants, roles, admin panel permissions) rather than guessed up front.

**Accept:**
- Production-unsafe throughout wk 1-10. MVP is local-only on founder's box; threat model accepts this.
- `DEV_BYPASS_AUTH` must be removed from any cloud deployment or gated by a kill switch. Checklist item for wk 12 hardening.
- Some Next.js/FastAPI middleware code gets rewritten in wk 11 when Entra lands. Small refactor, not a rewrite.

## Related

- ADR 0006 — soft multi-tenancy (auth middleware populates tenant context).
- ADR 0014 — webhook auth is separate (not user auth).
- `docs/context/stack-locks.md` — auth lock.
