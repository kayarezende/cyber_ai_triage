# 0008: Dual Splunk writeback (HEC + notable_update)

Date: 2026-04-15
Status: Accepted (refined by ADR-0018 on 2026-04-27 — adds `writeback_mode` config so non-ES tenants get `hec_only` mode rather than the dual writeback assumed here)

## Context

After investigation completes, the agent's verdict must reach the human analyst. The analyst's primary workflow is Splunk Enterprise Security (ES), viewing notable events. Two Splunk write paths exist and they serve different purposes:

- **HEC (HTTP Event Collector)** — ingests new events into a chosen index. Separate port (8088), different auth (token header, not session). Posts a new record.
- **`POST /services/notable_update`** (Splunk ES API) — updates an **existing** notable event. Adds comments, changes urgency/status. This is how analyst sees the notable change.

A HEC post does not modify the original notable. Without `notable_update`, the analyst's workflow never surfaces our verdict; they'd need to open our UI separately.

## Decision

**Dual writeback** on every investigation:

1. **`siem_notable_update` MCP tool** — POST to `/services/notable_update` attaching:
   - Verdict (true_positive / false_positive / benign / inconclusive).
   - Confidence score.
   - MITRE techniques.
   - One-line summary.
   - URL back to the Sentient Layer UI for deep dive.
   - Urgency override if detection rules flagged a killchain.
   Implementation: Splunk SDK low-level `service.post('notable_update', ...)` — session auth reuse.

2. **`siem_hec_post` MCP tool** — POST to `/services/collector/event` with the full OCSF Detection Finding as JSON. Indexes to `triage_verdicts` (a separate Splunk index). This is our queryable historical record.
   Implementation: `httpx` POST — different port, different auth from the SDK path. Not worth fighting the SDK abstraction.

Both tool names use the `siem_` prefix for SIEM-agnostic agent prompts. Sentinel equivalent will be a different implementation under the same contract.

## Alternatives considered

- **HEC only** — analyst never sees verdict in their ES workflow. Fatal UX regression.
- **`notable_update` only** — loses queryable historical record + bulk analytics across investigations over time.
- **Sidecar Splunk app with custom REST endpoints** — overkill for MVP; maintenance burden; customers don't want to install our Splunk app.
- **Custom Splunk dashboard pulled via API for UI** — adds latency + availability coupling. Rejected.

## Consequences

**Gain:**
- Analyst sees verdict + link inline in Splunk ES on the original notable. Zero context switch.
- Queryable history in `triage_verdicts` index for our own analytics.
- Both paths use OCSF Detection Finding format — consistent with ADR 0007.

**Accept:**
- Two network calls per investigation completion vs one.
- HEC requires a separate token in tenant config (`splunk_hec_token_encrypted` column alongside `splunk_token_encrypted`).
- ES-specific notable_update means this path doesn't exist in non-ES Splunk. Plain Splunk deployments will need a fallback (e.g., just HEC).

## Related

- ADR 0002 — SIEM-agnostic generic tool names.
- ADR 0007 — OCSF Detection Finding as the output format.
- ADR 0012 — Fernet encryption for the HEC token at rest.
