# 0018: Splunk writeback mode (`dual` vs `hec_only`)

Date: 2026-04-27
Status: Accepted

## Context

ADR-0008 specified dual Splunk writeback: `notable_update` REST (enriches the existing notable in Splunk Enterprise Security's analyst UI) + HEC post (indexes the OCSF finding to `triage_verdicts` for our own queryable record). The "Consequences" section of ADR-0008 acknowledged: _"ES-specific notable_update means this path doesn't exist in non-ES Splunk. Plain Splunk deployments will need a fallback (e.g., just HEC)."_ — but the fallback was never specified or locked.

A multi-agent review flagged this as a P2 — without an explicit decision, every prospective customer becomes an awkward _"do you have ES?"_ conversation, and the agent logic has no per-tenant switch to handle the no-ES case.

Splunk product structure:
- **Splunk Enterprise** is the base platform: indexing, SPL search, REST API, HEC ingest. Most companies running Splunk have this.
- **Splunk Enterprise Security (ES)** is a paid premium app installed on top of Enterprise. ES adds: notable events, the security workflow UI, the `notable_update` REST endpoint, risk-based alerting, MITRE ATT&CK navigation, and the analyst-facing UI that AU MSSPs typically buy Splunk for.
- ES costs ~A$10K+/yr per node minimum.

The founder's box runs Splunk Enterprise 10.0.2 (verified during planning, build `e2d18b4767e9`) and likely does **not** have ES installed. This is the dev environment for the entire MVP, so the MVP has to work on plain Splunk Enterprise.

## Decision

**Per-tenant `writeback_mode` config column**: `'dual'` | `'hec_only'`. Default `'hec_only'` (conservative — works on plain Splunk Enterprise).

```sql
ALTER TABLE tenants
  ADD COLUMN writeback_mode TEXT
    CHECK (writeback_mode IN ('dual', 'hec_only'))
    DEFAULT 'hec_only';
```

### `writeback_mode='dual'` (Splunk ES tenants)
Both writeback paths fire:
1. `siem_notable_update` MCP tool POSTs to `/services/notable_update` — verdict + confidence + MITRE techniques + summary + URL back to Sentient Layer UI + urgency override.
2. `siem_hec_post` MCP tool POSTs to `/services/collector/event` with the full OCSF Detection Finding to `triage_verdicts`.

UX: analyst sees verdict inline on their existing notable in Splunk ES + queryable history available in `triage_verdicts` index.

### `writeback_mode='hec_only'` (plain Splunk Enterprise tenants — default)
Only `siem_hec_post` fires. The `siem_notable_update` MCP tool short-circuits when the tenant config is `'hec_only'` — returns successfully with `mode='skipped'`, logs the skip in the audit log, no Splunk REST call made.

UX: analyst sees verdict in the Sentient Layer web UI only. The original Splunk notable is not enriched. Audit log explorer + investigation detail page surface the verdict + reasoning.

### Agent-prompt invariance
Both modes use the same MCP tool surface (`siem_notable_update` is always callable). The agent's prompt does not branch on `writeback_mode`. The mode-specific behaviour lives at the MCP server, not in the agent's reasoning. This keeps the agent prompts SIEM-agnostic (per ADR-0002) and lets a future tenant flip from `hec_only` to `dual` without prompt or graph changes.

### ES detection probe (post-MVP, not in wk-2 cleanup)
Tool to probe `/services/apps/local/SplunkEnterpriseSecuritySuite` on tenant onboarding to suggest `writeback_mode='dual'`. Admin confirms before the flip. Not auto-applied. Defer probe code to wk 8.

### Founder tenant
Default seed sets `writeback_mode='hec_only'` until ES install confirmed. If founder later installs ES, flip via admin UI or seed update.

## Alternatives considered

- **Lock `dual` as hard MVP prereq.** Cheaper to build (no `hec_only` mode) but excludes the founder's own dev environment. Rejected.
- **Auto-detect at writeback time.** First call probes for ES; cache the result. Rejected: hides mode from operator, makes UX surprising. Per-tenant explicit config is clearer.
- **Sidecar Splunk app exposing custom REST.** ADR-0008 already considered + rejected this. Stays rejected.
- **Build `dual` only and tell plain-Splunk customers to install ES.** Rejected: forces ~A$10K+/yr add-on on customers we don't even know yet. Reduces addressable buyer pool unnecessarily.

## Consequences

**Gain:**
- Founder's own MVP development on plain Splunk Enterprise works without compromise.
- Wider addressable pool — any Splunk Enterprise customer can use Sentient Layer, ES not required.
- ES customers get the strong dual writeback UX as an upsell.
- Per-tenant config makes future SIEM modes (Sentinel, CrowdStrike) follow the same pattern.

**Accept:**
- Two writeback paths to test. Mocked MCP + real-Splunk integration tests must cover both modes.
- `hec_only` UX is degraded — analyst has to switch to Sentient Layer UI to see verdicts. Mitigation: investigation detail page is a primary product surface anyway; the dual writeback was a UX bonus, not the core flow.
- Documentation has to explain the difference clearly to prospects.

## Related

- ADR-0008 — Dual Splunk writeback (this ADR refines the "plain Splunk needs fallback" gap acknowledged there).
- ADR-0002 — Splunk-first, SIEM-agnostic MCP abstraction (writeback_mode does not leak to agent prompts).
- `tenants` table schema — Phase 2 migration adds the column.
- `mcp/splunk/` — MCP server consumes the config (wk 8 implementation).
