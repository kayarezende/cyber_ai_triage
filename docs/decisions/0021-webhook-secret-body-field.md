# 0021: Webhook secret carrier — body field, supersedes ADR-0014 §header

Date: 2026-04-27
Status: Accepted (supersedes ADR-0014 §header carrier; preserves §threat-model)

## Context

ADR-0014 specified a `X-Webhook-Secret` HTTP header for the Splunk → `/api/incidents/ingest` webhook. Wk-4 implementation discovered that **stock Splunk Enterprise's built-in webhook alert action does not support custom headers**. Verified against the Splunk 10.x alerting manual; the existence of Splunkbase apps such as `Better Webhooks` and `Custom Alert Webhook` whose entire purpose is to add header support corroborates the limitation.

Three carriers were considered as replacements:

1. **Body field** — saved-search webhook payload templated with `"secret": "<value>"`. Works on stock Splunk; no app install. Sales-friction-free.
2. **Query parameter** — `?secret=<value>`. Works, but the secret leaks into URL access logs / proxy logs / browser history if a tab is opened. Bounded risk on single-host MVP but real.
3. **Splunkbase app for custom headers** — keeps ADR-0014 letter intact. Adds an install step on every prospect's Splunk box. Not viable for the GTM motion.

## Decision

**Body-field secret.** The Splunk saved-search alert action's webhook body is templated with `{"secret": "<INGEST_WEBHOOK_SECRET>", "result": "$result$"}`. FastAPI reads `request.body.secret` and `hmac.compare_digest`s against the env var.

The threat-model decision in ADR-0014 (shared secret, single-tenant MVP, no HMAC, no per-tenant tokens) is preserved verbatim — only the carrier changes.

## Alternatives considered

- **HMAC over body** — requires Splunk-side scripted alert action or a Splunkbase app to compute the signature. Same install friction as the header app option. Defer to wk-12 hardening if threat model demands.
- **Query parameter** — secret in URL leaks into access logs. Rejected.
- **Splunkbase webhook app** — adds dep on every prospect's Splunk install. Bad for sales motion. Rejected.

## Consequences

**Gain:**
- Works on every prospect's Splunk install with zero app dependency. Zero sales friction.
- Simpler to implement than HMAC (no signing, no timestamp, no replay window).
- Migration path stays open: per-tenant slug routing + per-tenant secret hash table at wk-11 alongside Entra SSO.

**Accept:**
- Secret is in the request body. Today: intra-LAN cleartext (founder's box). Wk-12 hardening adds TLS to Traefik.
- Splunk audit log entries for the saved-search definition include the templated body, so the secret is visible to any operator with `admin_all_objects`. **Operators must treat saved-search exports as sensitive** — `splunk-setup.md` §5.3 notes this.

## Related

- ADR-0014 — original shared-secret webhook auth (header carrier obsolete; threat-model rationale unchanged).
- ADR-0011 — user auth (separate concern from webhook auth).
- ADR-0017 — audit hash chain (every ingest writes an `incident_ingested` row regardless of carrier).
