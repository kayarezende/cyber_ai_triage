# 0014: Shared-secret webhook auth for MVP

Date: 2026-04-15
Status: Accepted (carrier §refined by ADR-0021 — stock Splunk webhook alert action does not support custom headers; secret moved to body field. Threat-model decision unchanged.)

## Context

Splunk sends incident notifications to `/api/incidents/ingest` via HTTP POST from a saved search alert action. Anyone who knows the URL can send fake incidents unless we authenticate. MVP is local-only on founder's box — threat model is low but not zero.

Options:
- **Shared secret header** — `X-Webhook-Secret: <value>` compared to env var.
- **HMAC signature** — `X-Signature: sha256(body + secret)` — proves body integrity + prevents replay if timestamp included.
- **Per-tenant bearer token** — each tenant has unique token, lookup by token identifies tenant.
- **Mutual TLS** — strong but heavy Splunk-side config.

## Decision

**Shared secret env var for MVP.** Env var `INGEST_WEBHOOK_SECRET` set at startup. Splunk saved search alert action configured with `X-Webhook-Secret: <secret>` header. FastAPI middleware checks header equals env var; 401 otherwise.

HMAC + per-tenant tokens deferred post-MVP.

## Alternatives considered

- **HMAC signatures from day 1** — stronger (proves body integrity, replay-resistant) but adds Splunk-side config. Over-investment for MVP threat model.
- **Per-tenant bearer tokens from day 1** — needed for multi-tenant SaaS but MVP has one tenant. Premature.
- **mTLS** — rejected as operational overkill.
- **No auth** — anyone on the network can forge incidents. Rejected.

## Consequences

**Gain:**
- Trivial implementation (~10 lines FastAPI middleware).
- No Splunk-side cryptographic setup required.

**Accept:**
- Secret is a single shared value across all tenants (fine for single-tenant MVP).
- No message integrity — captured request can be replayed indefinitely. OK for MVP; fix with HMAC + timestamp when threat model demands.
- Secret in env file; compromise of `.env` = forged-request capability. Same risk class as any env-borne secret.

## Related

- ADR 0012 — secret encryption (Fernet) — different secrets, same env-based pattern.
- ADR 0011 — user auth (separate concern from webhook auth).
