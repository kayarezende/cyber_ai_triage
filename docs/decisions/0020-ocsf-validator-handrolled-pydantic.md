# 0020: OCSF 1.3.0 validator — hand-rolled Pydantic v2

Date: 2026-04-27
Status: Accepted (refines ADR-0007 §validator)

## Context

ADR-0007 locks OCSF 1.3.0 as the wire schema for both incident-side ingest (Splunk notable → OCSF on receive) and outbound writeback (OCSF Detection Finding → Splunk HEC + `notable_update`). The decision left the validator implementation choice open: _"`py-ocsf-models` pinned if supports 1.3.0; else hand-rolled Pydantic."_

A wk-2 spike resolved this:

- `py-ocsf-models >=0.5` (current PyPI release line) targets **OCSF 1.5.0**. There is no maintained release line targeting 1.3.0 specifically. Downgrading to a stale 1.3.0 release would inherit unmaintained code; staying on the 1.5.0 line drifts from our locked schema and creates field-presence inconsistencies (1.5.0 added/renamed fields vs 1.3.0).
- For the MVP, we only emit one OCSF root class — Detection Finding (`class_uid 2004`) — for writeback. The wk-3 incident mapper consumes the same root class. Modelling that one class + its dependent objects is ~150 lines of Pydantic.
- The Detection Finding spec is short enough to read carefully in an afternoon. For a security product, reading the schema we conform to is the right activity anyway.

## Decision

**Hand-roll Pydantic v2 models in `libs/ocsf/`, scoped to OCSF Detection Finding (class_uid 2004) + the dependent objects it references.**

Initial scope (landed wk 2):

- `DetectionFinding` root class — `class_uid 2004`, `category_uid 2`, `activity_id`, `type_uid` (auto-derived = `class_uid * 100 + activity_id`), `severity_id`, `time` (epoch ms), `metadata`, `finding_info`, `confidence`, `disposition_id`, `disposition`, `attacks[]`, `message`.
- Nested objects: `Metadata`, `Product`, `FindingInfo`, `Analytic`, `Attack`, `MitreTactic`, `MitreTechnique`.
- Sentient Layer extensions as top-level typed fields: `verdict` (enum), `evidence_url`, `mitre_techniques: list[str]` (denormalised T-codes alongside structured `attacks[]`).
- `to_hec_dict()` serialiser renames extension fields to `sentient_*` namespace (avoids future-OCSF field collision).
- `validate_detection_finding(payload: dict) -> DetectionFinding` entrypoint for the wk-3 mapper.

Out of scope today (add when a customer requirement actually needs them, not preemptively):

- Actor / src_endpoint / dst_endpoint / device — Splunk-notable-side incident mapping (wk 3 may add a subset).
- Evidences[] / Enrichments[] — wk 8 if the agent's evidence manifest needs to ride inline in the OCSF payload (current design has it in MinIO, referenced via `evidence_url`).
- Risk_score / Risk_level_id — wk 9 if dashboard surfaces it.
- Other OCSF root classes (Activity Logging 1001+, Findings non-2004, etc.) — only when a separate workflow needs them.

## Alternatives considered

- **`py-ocsf-models` pinned to a 1.3.0-targeting release.** No such maintained release line exists. Rejected.
- **`py-ocsf-models` 1.5.0 with manual field-shape adjustments.** Drift between our wire format and the library's schema becomes a perpetual maintenance tax. Rejected.
- **Generate Pydantic models from the OCSF JSON schema metaschema.** Defensible long-term but heavyweight for an MVP — adds a build-time codegen step + a vendored copy of the OCSF 1.3.0 schema repo. Rejected for now; revisit if we ever model >5 root classes.
- **Skip Pydantic; use plain dicts + JSON schema validation via `jsonschema`.** Loses static typing in the agent + mapper; harder to refactor. Rejected.

## Consequences

**Gain:**
- Pinned to OCSF 1.3.0 by construction — no upstream library drift can leak schema-version inconsistency.
- Static typing across the orchestrator + mapper + writeback path.
- Easy to add custom Sentient Layer extension fields without forking a third-party model.
- The act of writing the model forces close reading of the spec — appropriate for a security product where wire-format mistakes propagate to detection rules and customer dashboards.

**Accept:**
- Future OCSF version upgrades (1.4.x, 1.5.x) require manual model updates. Mitigated by: (a) we only model what we use, so the surface to update is small; (b) ADR-0007 already locks 1.3.0 — version bumps require a new ADR anyway.
- We are responsible for spec correctness — no upstream library catches our mistakes. Mitigated by: tests against the published Splunk-OCSF Detection Finding example + the wk-3 mapper exercising round-trips against real Splunk notables.

## Related

- ADR-0007 — OCSF 1.3.0 + MITRE ATT&CK as enforced standards (this ADR specifies the validator implementation choice that ADR-0007 left open).
- `libs/ocsf/src/sentient_ocsf/detection_finding.py` — the model.
- `libs/ocsf/tests/test_detection_finding.py` — validation + extension-namespacing tests.
- ADR-0008 + ADR-0018 — writeback (consumes the Detection Finding model wk 8).
