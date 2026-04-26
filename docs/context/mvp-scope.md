# MVP Scope + Timeline

**Timeline:** 13 weeks solo full-time + 2 weeks buffer = 15 weeks worst case.
**Deployment:** Single Docker Compose on founder's on-prem Splunk box.
**Role:** Founder = design partner #0. External design partners wk 12+.

---

## In-scope for MVP

### Ingest + enrich
- Splunk saved search + alert action → webhook POST to `/api/incidents/ingest`.
- Splunk on-prem connection per tenant (service account token, encrypted in DB).
- OCSF 1.3.0 Detection Finding normalization on ingest.
- Splunk-native enrichment only (ad-hoc SPL via MCP tools).

### Agent
- 2-tier architecture:
  - **Tier 1 — Triage** (one-shot, no tools): classify severity/confidence/MITRE guesses/entities.
  - **Tier 2 — Investigation** (LangGraph multi-turn with MCP tools): plan → SPL → correlate → draft verdict.
- **Review role** (MVP): second LLM call critiques the draft verdict before HITL (catches hallucinations).
- Deterministic post-pass: 10 seed detection rules applied to MITRE technique sets.
- Evidence manifest `evidence.json` to MinIO per investigation.
- Prompt caching on system + incident + MITRE blocks.

### LLM routing (per-role, configurable)
- Admin-panel config per role: primary model + fallback chain + max_tokens + timeout + temperature.
- **App-side fallback loop** (try primary → catch error → log per-attempt usage row → try next). Drops OpenRouter native `models[]`. See ADR-0015.
- Per-attempt row in `usage` table (`attempt_num`, `model_requested`, `model_used`, status enum, latency, tokens, cost). Failure mid-loop still leaves audit trail.

### HITL
- LangGraph `interrupt()` at `await_approval` node.
- `hitl_policies` JSONB rule engine. MVP default = always human.
- Analyst approves from web UI → graph resumes.

### Writeback
- Per-tenant `writeback_mode` config (`dual` | `hec_only`). See ADR-0018.
- `dual` (Splunk ES tenants): `notable_update` REST attaches verdict to original notable + HEC post to `triage_verdicts` index.
- `hec_only` (plain Splunk Enterprise tenants — default): HEC post only. `notable_update` is no-op (returns `mode=skipped`). Analyst sees verdict in Sentient Layer UI only.
- OCSF Detection Finding format on both writeback paths.

### Standards
- MITRE ATT&CK STIX cache seeded on build.
- OCSF 1.3.0 schema enforced in + out.

### Storage
- Postgres 16 with soft multi-tenancy (tenant_id + RLS, `WITH CHECK` on all tenant-scoped tables, `IS NULL OR ...` on global-capable tables — see Phase 2 migration).
- Hash-chained `audit_log` (`previous_hash` + `hash_scope`) with `audit_writer` DB role split + UPDATE/DELETE-blocking triggers. See ADR-0017.
- MinIO with Object Lock + versioning enabled at bucket creation, for evidence artifacts + raw Splunk payloads.
- Redis for investigation job queue.
- Unlimited retention in MVP.

### Auth
- Dev bypass only MVP (env flag + simple email).
- Entra SSO wk 11 pre-demo.

### Web UI (Next.js 15)
- Investigation detail page: verdict, reasoning trace, evidence chain, MITRE matrix heatmap.
- Approval UI (resumes LangGraph thread).
- Audit log explorer (filterable, hash-chain integrity verifiable).
- Time-travel replay (full step-by-step scrubber over LangGraph checkpoints).
- **Admin panel (MVP scope)**: tenant management (Splunk host/tokens/HEC token, Entra config), LLM credentials (master OpenRouter key + per-tenant BYO override columns surfaced when sovereign-mode lands), per-role LLM config (primary model + fallback chain dropdown + max_tokens + timeout + temperature), budget caps (per-investigation + monthly), users, usage dashboard.
- **Admin panel (post-MVP)**: HITL drag-drop rule builder (MVP uses raw JSONB editor + seed rows), detection-rule editor (MVP uses seed rows), white-label theming, sovereign-mode toggles in admin UI (DB columns present from MVP, UI exposure post-MVP).

### Observability
- `structlog` JSON to stdout.
- LangSmith for agent tracing.

### Eval
- 50+ labeled incidents: Splunk BOTS v3 (derive labels from CTF keys) + Atomic Red Team (labeled by construction) + honeypot (labeled by construction) + hand-label ambiguous.
- Ship gate: ≥85% verdict agreement, ≥0.70 MITRE F1.

---

## Out-of-scope for MVP (deferred)

| Feature | When |
|---|---|
| Microsoft Sentinel connector | Wk 10-14 or post-MVP |
| CrowdStrike Falcon connector | Month 4-6 |
| Defender XDR connector | Month 4-6 |
| Public threat intel enrich (VT, AbuseIPDB, GreyNoise) | Month 4 |
| Auto-response / containment | Month 9 (opt-in) |
| White-label branding | Month 9 |
| Hard tenant isolation | Month 6 |
| SOC2 Type I attestation | Month 9 |
| IRAP PROTECTED | Year 2 (with paying government-adjacent customer) |
| LLM roles: `summarize`, `entity_extraction` | Post-MVP (schema present, disabled) |
| Multi-agent (specialist agents: phishing, insider, ransomware) | Month 6+ |
| HMAC signature webhook auth | Post-MVP |
| Per-tenant API tokens for Splunk ingestion | Post-MVP |
| Admin UI for HITL rule building (drag-drop) | Post-MVP (raw JSONB editor + seed rows in MVP) |
| Admin UI for detection-rule editing | Post-MVP (seed rows in MVP) |
| Automated secret rotation | Post-MVP |
| Kubernetes / ECS / Terraform | Post paying customer |
| Split control/data plane topology | Post first external customer |
| Loki / Grafana / Prometheus observability | Post-MVP |
| Sovereign-mode tier (Bedrock Sydney / Azure AU East routing, LangSmith off, BYO LLM keys) | Post-MVP. **DB surface present from MVP** (per-tenant `byo_*_key_encrypted`, `llm_region_constraint`, `langsmith_enabled` columns). Activation = feature flag + admin UI. See ADR-0016. |

---

## Week-by-Week (13 weeks + 2 buffer)

- **Wk 0** — Prep (Splunk ES version doc, OCSF validator pick, API keys).
- **Wk 1** — Scaffolding + MITRE seed + BOTS v3 load + structlog.
- **Wk 2** — MCP Splunk server v1 + LangGraph framework validation.
- **Wk 3** — OCSF normalization layer.
- **Wk 4** — Ingest path end-to-end (webhook → queue → worker → stub verdict).
- **Wk 5** — Tier 1 triage via OpenRouter + per-role LLM config tables.
- **Wk 6** — Tier 2 LangGraph skeleton + checkpointer + parallel labeling begins.
- **Wk 7** — Tier 2 completeness + prompt caching + **review role** wired.
- **Wk 8** — Detection rules + HITL `interrupt()` + dual Splunk writeback.
- **Wk 9** — Web UI core: investigation detail + approval + audit log + time-travel.
- **Wk 10** — Web UI admin panel + eval harness setup.
- **Wk 11** — Quality iteration (prompt/rule tuning) + Entra SSO.
- **Wk 12** — Hardening + security review + demo + external design partner outreach.
- **Wk 13** — Buffer / slippage.
- **Wk 14-15** — Buffer / docs completion.

Detailed milestones: `tasks/todo.md`.

---

## Ship gate (MVP done)

- ≥85% verdict agreement vs senior analyst on golden set of 50 labeled incidents.
- ≥0.70 MITRE F1 on golden set.
- Latency p50 < 5min / p95 < 15min.
- All MCP tool calls + LLM calls audit-logged.
- `docker compose up` on clean machine brings full stack healthy.
- Demo video recorded.
- Self-hosted on founder's VPS as internal design partner #0.
