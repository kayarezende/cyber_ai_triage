# 0007: OCSF 1.3.0 + MITRE ATT&CK as enforced standards

Date: 2026-04-15
Status: Accepted

## Context

SOC tooling has a schema-chaos problem. Every SIEM emits events in its own shape (Splunk ES notables, Sentinel alerts, CrowdStrike detections) and every detection engine speaks its own threat taxonomy. This blocks:
- SIEM-agnostic agent prompts (agent would need to know each SIEM's quirks).
- Cross-vendor detection rules.
- Portable verdicts that downstream tools can consume.

Two standards have meaningful industry adoption:
- **OCSF (Open Cybersecurity Schema Framework)** — cross-vendor event schema backed by Splunk, Microsoft, AWS, Cisco. 1.x spec stable.
- **MITRE ATT&CK** — de-facto standard threat taxonomy. Every SOC analyst speaks it.

## Decision

**Enforce OCSF 1.3.0 end-to-end.** Splunk notable → OCSF Detection Finding (class_uid 2004) on ingest. Agent output → OCSF Detection Finding on writeback.

**Enforce MITRE ATT&CK for threat mapping.** Every verdict carries `mitre_techniques: []` (array of T-codes). Severity floor derived from technique impact matrix. Detection rules key off technique sets.

**Pin OCSF at 1.3.0.** Do not chase latest spec revisions.

**MITRE STIX 2.1** seeded from `mitre/cti` GitHub into `mitre_techniques` Postgres table at build time. Refresh via `make refresh-mitre`.

## Alternatives considered

- **No normalization; feed agent raw SIEM events** — simplest MVP but binds agent prompts to Splunk's schema. Rewriting for every new SIEM = high. Rejected.
- **ECS (Elastic Common Schema)** — strong alternative but narrower industry backing than OCSF. Rejected.
- **Custom internal schema** — full control but we'd be inventing standards that no customer speaks. Rejected.
- **OCSF 1.4/latest** — spec still evolving. Pin avoids breakage.

## Consequences

**Gain:**
- SIEM-agnostic agent prompts — agent sees OCSF, doesn't care if source was Splunk or Sentinel.
- Detection rules are MITRE technique sets, not free text.
- Compliance story strengthens (OCSF + MITRE are frameworks auditors recognize).
- Verdict output is portable — downstream SOAR/ticket systems can consume OCSF natively.

**Accept:**
- Translation layer (Splunk → OCSF) is code we write + maintain. Testing across many notable variants required.
- OCSF 1.3.0 pinning means we miss spec improvements. Revisit annually.
- MITRE STIX refresh is an ongoing ops task. Automate via build-time make target.

## Related

- ADR 0002 — generic MCP tool names (enables OCSF-in-OCSF-out pipeline).
- ADR 0008 — dual Splunk writeback uses OCSF Detection Finding format.
- `docs/ocsf-mapping.md` — field-by-field mapping spec (to be written).
