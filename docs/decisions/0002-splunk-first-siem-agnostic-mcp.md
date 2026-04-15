# 0002: Splunk-first, SIEM-agnostic MCP abstraction

Date: 2026-04-15
Status: Accepted

## Context

MVP needs a first SIEM to integrate. Founder has on-prem Splunk. AU market mix is Splunk-heavy (banks, gov, APRA shops) + Sentinel-heavy (M365 E3/E5 mid-market).

The product eventually needs to support multiple SIEMs (Sentinel, CrowdStrike, Defender XDR). If MCP tool names are SIEM-specific (`splunk_search`, `splunk_get_notable`), adding a new SIEM means duplicating tools *and* rewriting agent prompts. If MCP tool names are generic (`siem_query`, `siem_get_notable`), adding a new SIEM is just a new MCP server implementation — agent prompts stay constant.

## Decision

- **MVP wedge: Splunk on-prem** (founder's box). Leverages founder's existing infra + AU sovereignty positioning (Splunk on-prem ≠ cloud).
- **Generic MCP tool names** — `siem_query`, `siem_get_notable`, `siem_get_entity_history`, `siem_process_tree`, `siem_lookup_ioc`, `siem_notable_update`, `siem_hec_post` (mapped Splunk → generic) — so agent prompts are SIEM-agnostic from day 1.
- Sentinel connector targeted wk 10-14 or early post-MVP.
- Product positioning: "SIEM-agnostic AU AI SOC, Splunk-first."

## Alternatives considered

- **Sentinel-first** — larger AU mid-market TAM but no free founder dev environment; would require test tenant setup before any code. Defers to wk 10-14.
- **Dual connector from day 1** — doubles MCP work for solo dev. Vetoed.
- **Splunk-specific tool names** — simpler wk 1-8 but forces agent-prompt rewrites per SIEM later. Rejected as false economy.

## Consequences

**Gain:**
- Sovereignty story stronger (Splunk on-prem is literally in customer DC).
- Founder dogfood advantage — iterates hourly on own data without customer cooperation.
- Adding Sentinel/CrowdStrike later is an MCP server impl, not an agent-prompt rewrite.
- Positioning stays broad ("SIEM-agnostic") rather than "Sentinel-only".

**Accept:**
- AU mid-market Sentinel TAM partially unserved until wk 10-14.
- Abstraction tax — internal mapping from Splunk-specific operations to generic tool contracts. Small cost.
- Need to design the generic tool contract carefully so it doesn't over-fit Splunk semantics.

## Related

- ADR 0008 — Dual Splunk writeback (HEC + notable_update).
- `docs/context/stack-locks.md` — current MCP tool list.
