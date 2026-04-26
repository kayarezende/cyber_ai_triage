# Plan: Sentient Layer — AI SOC Triage for Australian MSSP + Mid-Market

**Domain:** `sentientlayer.ai`
**MVP wedge:** Splunk on-prem triage agent (founder's own Splunk box = dev environment + design partner #0).
**Future SIEMs:** Microsoft Sentinel wk 10-14 / post-MVP. CrowdStrike + Defender XDR month 4-6+.

## Context

**The problem.** AU orgs drown in SIEM/EDR alerts. ISC2 2025: 95% report material skills gaps; SOC analysts burn out (70% of juniors quit <3yr). Microsoft/Omdia 2026: 46% of alerts are false positives. IBM 2025: global avg breach cost USD 4.44M. Regulatory pressure climbing: SOCI Act, APRA CPS 234/230, Essential Eight ML2 mandatory for 98 Commonwealth entities, Privacy Act penalties up to A$50M. Post-Optus/Medibank, AU buyers want Australian-built tooling and a credible sovereignty story.

**Why now.** AI SOC category is at Gartner's Peak of Inflated Expectations (2025) — category real, already commoditizing. Dropzone ($37M B, 11x ARR), Prophet ($30M A), 7AI ($130M A, largest cyber A in history) have US enterprise. **No credible AU-HQ AI SOC product exists.** Microsoft Security Copilot is free with M365 E5 — existential threat to horizontal US-facing plays, non-threat to AU MSSP channel.

**Why this founder.** SOC operator + AI/ML engineer = rare wedge. Can build MVP solo or lean, sell credibly to MSSPs, bootstrap under 12 months.

**Intended outcome.** Within 12 months, 2-3 paid AU MSSP pilots + 1-2 direct AU mid-market customers on Splunk-first triage agent (Sentinel connector deferred wk 10-14), with compliance-native posture (Essential Eight-aligned, audit-complete hash-chained logging) positioned to win sovereignty-sensitive deals via a separately-priced sovereign-mode tier post-MVP.

---

## Strategy

### Positioning
**"Australian-built AI SOC analyst — Splunk-first, OCSF-native, audit-complete."**

A separately-priced **sovereign-mode tier** (BYO Bedrock Sydney / Azure AU East routing, LangSmith disabled, customer-supplied LLM keys, region-constrained provider routing) ships post-MVP for sovereignty-sensitive tenants. **MVP is not sovereign** — it routes through OpenRouter (US infrastructure) and LangSmith SaaS for tracing. The DB surface for sovereign-mode is in place from MVP day 1 (per-tenant BYO key columns + region constraint + langsmith toggle), so activation is a feature flag, not a migration.

Wedge stack (in priority):
1. **Australian-built** — Sentient Layer Pty Ltd, AU support, AU pricing, AU customer-success ownership. Path to sovereignty via the sovereign-mode tier. See ADR-0016.
2. **Compliance-native** — Essential Eight ML2 mapping, APRA CPS 234 alignment, hash-chained audit log (see ADR-0017), evidentiary chain-of-custody for post-incident review.
3. **MSSP multi-tenancy** — soft tenant isolation MVP (`tenant_id` + RLS), hard isolation month 6, channel-friendly pricing, white-label option month 9.
4. **Splunk-first wedge** — founder's own Splunk Enterprise box = dev environment. AU MSSP market still heavily Splunk-deployed. Sentinel connector ships wk 10-14 (largest AU enterprise footprint).

### What we are NOT doing
- Not competing horizontally with Dropzone on US mid-market. They've won that race.
- Not chasing CrowdStrike/Palo Alto/Google stacks at MVP — breadth kills bootstrap timelines.
- Not doing consumer. Research shows graveyard economics.
- Not pursuing IRAP PROTECTED certification in year 1 (A$150-300K + 6-9mo). Design for it; pursue with first paying government-adjacent customer co-funding.
- Not selling to Tier-1 MSSPs (CyberCX, Telstra Purple) in year 1 — 9-12mo procurement kills bootstrap.
- **Not claiming sovereignty in MVP.** OpenRouter (US) + LangSmith SaaS (US) are MVP defaults. Sovereign-mode tier ships post-MVP as a paid feature with BYO Bedrock Sydney / Azure AU East routing + LangSmith off + BYO keys.

### ICP prioritization
**Primary: Tier-2/3 AU MSSPs** — Sekuro, Content Security, Shearwater, Triskele Labs, Bitwise, Gridware, Jaarvis. These need differentiation vs. CyberCX, have faster decision cycles, will co-build, and bring compounding customer exposure.
**Secondary: AU mid-market direct (100-1000 employees, non-regulated)** — faster close, smaller ACV, generates case studies for MSSP sales, covers runway.

---

## Product (MVP scope)

### Core: Splunk on-prem AI triage agent
Input: Splunk notable event (via saved-search alert action → webhook to `/api/incidents/ingest`).
Output: OCSF Detection Finding (verdict, confidence, MITRE ATT&CK mapping, evidence chain, suggested actions) written back to Splunk via dual writeback (HEC + ES `notable_update` when ES installed; `hec_only` mode when not — see ADR-0018).

**MVP capabilities (ship in ~13 weeks + 2 buffer):**
1. **Ingest & enrich** — pull notable + entities (IPs, users, hosts, files) from Splunk via SDK. Splunk-native enrichment only via ad-hoc SPL through MCP tools. Public threat intel (VT/AbuseIPDB/GreyNoise) deferred to month 4.
2. **Autonomous investigation** — multi-role LLM pipeline (triage → investigation → review). Investigation role is LangGraph multi-turn with MCP tools. Per-role model config (primary + fallback chain) configurable in admin panel. App-side fallback loop with per-attempt audit ledger (see ADR-0015).
3. **Evidence & audit** — every tool call, LLM call, user action logged to hash-chained `audit_log` table. Append-only via DB role split + triggers (see ADR-0017). MinIO Object Lock for evidence artifacts.
4. **Human-in-loop** — all actions gated by LangGraph `interrupt()`. MVP default = 100% human approval. JSONB `hitl_policies` rule engine. No auto-response in MVP.
5. **MSSP multi-tenancy** — soft isolation MVP via `tenant_id` + Postgres RLS. Per-tenant LLM config + budget caps + Splunk creds. Hard isolation deferred month 6.

**Deferred (post-MVP):**
- Microsoft Sentinel connector (wk 10-14 / post-MVP).
- CrowdStrike Falcon connector (month 4-6).
- Microsoft Defender XDR alerts (month 4-6).
- Public threat intel enrichment (VT, AbuseIPDB, GreyNoise) (month 4).
- Sovereign-mode tier (Bedrock Sydney / Azure AU East routing, LangSmith off, BYO LLM keys) — DB surface present from MVP, runtime ships post-MVP.
- Phishing/BEC specialized agent (month 7).
- Auto-response / containment (month 9, opt-in).
- White-label branding (month 9).
- HITL drag-drop rule builder UI (post-MVP — MVP uses JSONB editor + seed rows).

---

## Architecture (Docker Compose first, cloud later)

**Deployment model for MVP**: everything runs in Docker Compose. Single `docker-compose.yml` brings up the whole stack on a laptop or any VM. No cloud lock-in, no infra cost, no Terraform yet. Same containers later deploy to AWS Sydney (ECS/Fargate) or customer's own infra — which is itself a selling point for sovereignty-conscious buyers who want self-host.

**Containers (services in docker-compose.yml):**
- `orchestrator` — Python, LangGraph StateGraph + `langchain-mcp-adapters` + MCP tool clients. Stateful via Postgres checkpointer; HITL via `interrupt()`. Handles investigation planning + execution + app-side LLM fallback loop.
- `web` — Next.js 15 + Tailwind frontend. Investigation viewer (verdict + reasoning trace + evidence chain + step replay), tenant admin (creds + LLM config + budgets + usage), audit log explorer.
- `api` — Thin FastAPI layer between `web` and `orchestrator`. Auth, tenant scoping, rate limiting.
- `postgres` — Postgres 16. Tenants, users, investigation metadata, hash-chained audit log, per-attempt LLM usage, per-role LLM config, HITL policies, MITRE technique cache, detection rules.
- `redis` — job queue (investigations are async), prompt cache keys, rate limits.
- `minio` — S3-compatible object store with Object Lock + versioning enabled at bucket creation. Audit log artifacts, investigation evidence bundles, raw Splunk payloads. Swap to real S3 + Object Lock in production.
- `mcp-splunk` — MCP server wrapping `splunk-sdk` (PyPI) for search + ES endpoints + `httpx` for HEC. Generic SIEM-agnostic tool names (`siem_query`, `siem_get_notable`, `siem_notable_update`, `siem_hec_post`).
- `worker` — background investigation runner pulling jobs from redis.
- `traefik` — reverse proxy, TLS termination for local hostnames (`app.triage.local`, `api.triage.local`).

**Stack:**
- **LLM**: OpenRouter for all roles + all tiers. Per-role config (primary model + fallback chain + max_tokens + timeout) in `llm_role_config` table. App-side fallback loop logs each attempt to `usage` table (see ADR-0015). MVP dev default `google/gemini-3-flash-preview`. Prod defaults: `anthropic/claude-opus-4-7` (investigation), `anthropic/claude-sonnet-4-6` (review), `anthropic/claude-haiku-4-5` (triage) — all admin-overridable via per-role config rows. Prompt caching aggressively pursued; cache hit rate is an eval target wk 7, not a budget assumption (OpenRouter passthrough has provider/TTL/sticky-routing caveats).
- **Hosting**: Docker Compose locally + on founder's on-prem Splunk box for MVP. Migrate to AWS Sydney (ap-southeast-2) or customer-hosted when first paying customer requires it — same containers, ECS task definitions or customer-tenant install.
- **Data**: Customer Splunk data stays in customer's Splunk. We orchestrate via Splunk SDK from our control plane (founder's box for MVP). We store only: investigation metadata, hash-chained audit logs, our own prompts/responses. Encrypted at rest (Fernet via `TENANT_SECRET_KEY` for tenant secrets in Postgres; MinIO SSE for object store).
- **Agent framework**: LangGraph + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`. Chosen for native HITL `interrupt()`, resumable investigations via Postgres checkpointer, and multi-agent runway for month 6+ specialists. LLM calls go through our `LLMRouter` wrapper (not `langchain-anthropic`) so the app-side fallback loop owns per-attempt logging.
- **Frontend**: Next.js 15 + Tailwind. App Router. Server components default. Strict TS.
- **Auth**: Dev bypass (`DEV_BYPASS_AUTH=1`) MVP. Entra ID SSO wk 11. SCIM is post-MVP.
- **Compliance primitives from day 1**: per-tenant encrypted Splunk + HEC tokens, hash-chained audit log with `previous_hash` + `hash_scope` + DB role split (see ADR-0017), MinIO Object Lock for evidence artifacts, Essential Eight mapping doc (wk 13).

**Why Docker Compose is the right bootstrap call:**
- Zero cloud cost during 12-month runway. Runs on founder's laptop or a A$20/mo Hetzner box for demos.
- Customers who want self-host get it for free — strong sovereignty story ("we ship you a compose file, your data never leaves your walls").
- Easy path to production: compose → AWS ECS (via `ecs-cli compose` or manual task defs), compose → customer-hosted, compose → airgapped. Same artifacts.
- Single-command onboarding for design partners: `git clone && docker compose up`.

**What we're NOT building:**
- Our own foundation model. Claude/Gemini are the accelerant, not the moat.
- A SIEM. We plug into Splunk (and Sentinel post-MVP), not replace either.
- A SOAR. We output recommended actions; humans or existing SOAR (Tines/Torq/Splunk playbooks/Sentinel playbooks) execute.
- Kubernetes, Terraform, service mesh, or anything else that burns weeks before product-market fit.

---

## Go-to-market (12-month bootstrap)

### Months 0-3: Build + founder-as-design-partner
- Ship MVP (Splunk notable → investigation report) on founder's own Splunk Enterprise box. Founder = design partner #0 throughout build (wks 1-12).
- External design-partner outreach begins **wk 12-15** (not earlier — pitching while still scaffolding wastes calls). Targets: 1 Tier-2/3 MSSP, 2 mid-market AU companies (leverage founder's network).
- Weekly feedback loop with externals from wk 13. Ship fixes in days.
- Begin SOC2 Type I controls (self-attested is fine at MVP).

### Months 3-6: First paid pilots
- Convert 1-2 design partners to paid pilot (A$2-5K/mo MSSP, A$1-2K/mo mid-market).
- Publish: "How we built a sovereign AI SOC" blog, E8 mapping doc, 1 detailed case study.
- Attend AISA CyberCon (Canberra), pitch MSSPs directly.
- Hire: 0 people. Stay solo or 2-co-founder.

### Months 6-9: Channel motion
- Sign 2-3 MSSP reseller/co-sell agreements. Revenue share 20-30%.
- Ship: CrowdStrike connector, white-label UI, SOC2 Type I attestation.
- Target A$15-25K MRR by month 9.

### Months 9-12: Funding decision point
- Bootstrap break-even possible at ~A$30K MRR if solo (no salary).
- **Three paths** at month 12:
  - **Cash-flow sustainable**: Keep growing, don't raise. Build for regional acquisition (Macquarie, Telstra, CyberCX) within 3 years.
  - **Traction justifies US seed**: Delaware C-Corp flip, US VC ($2-5M), open SF office, target US mid-market.
  - **Signal weak**: Kill criteria (see Risks). Redeploy.

### Corporate structure
- Register AU Pty Ltd now. Claim **R&D Tax Incentive (43.5% refundable)** for FY26 and FY27 — biggest bootstrap lever available.
- Do NOT set up Delaware C-Corp until US seed decision. Premature flip burns A$30-50K in legal.

---

## Unit economics (rough)

**Costs per pilot tenant/month:**
- LLM inference: ~A$200-800/mo per mid-size tenant (1K-5K alerts/mo triaged), assuming production cache hit rate hits the wk-7 eval target. **Cache hit rate is an eval target, not a budget assumption** — OpenRouter passthrough caching has provider/TTL/sticky-routing caveats, so wk-7 will measure actuals before any pricing is locked.
- Infra: ~A$150-300/mo per tenant (Docker host or AWS Sydney).
- Total COGS: **A$350-1,100/mo (assuming cache target met)**. Gross margin at A$2K pricing: 45-82%. Re-validate post wk-7 eval.

**Pricing assumption year 1:**
- MSSP: A$2-5K/mo/tenant they onboard. Or A$500-1.5K per seat in their SOC.
- Mid-market direct: A$1-3K/mo flat, up to N alerts/mo.

**Not token-priced.** Research flags token-based pricing as buyer pain. Flat-rate per tenant, unlimited alerts (with fair-use cap).

---

## Competitive defensibility

| Threat | Response |
|---|---|
| Dropzone/Prophet enter AU | They sell US-tenanted SaaS. We're in-country, IRAP-roadmapped. Wins gov-adjacent, loses neutral. |
| Microsoft Security Copilot free with E5 | Copilot requires E5 licenses (A$57/user/mo × whole org). Most AU mid-market on E3. We serve the gap. For E5 shops, we integrate with Copilot rather than replace it. |
| CyberCX builds in-house | Possible. Mitigate by locking in Tier-2/3 MSSPs first; make them harder to replace. |
| Claude + MCP lets any analyst DIY | Real risk. Defensibility = tenant isolation, compliance pack, MSSP operations, investigation quality (prompts + evals), not the LLM. |
| Consolidation wave | Base-case outcome is regional acquisition (Macquarie, Telstra Purple, Optus, CyberCX). Build to be acquirable. |

---

## Key files & next steps

Repo is bootstrapped — compose stack, scaffolded apps, initial migration, MITRE seed all exist as of wk 1-2 (see `tasks/todo.md` for current state). Continued build order:

1. **`docker-compose.yml` + override** — extant. Services: orchestrator, web, api, postgres, redis, minio, mcp-splunk, worker, traefik.
2. **`.env.example`** — extant. Required: `SPLUNK_HOST`, `SPLUNK_TOKEN`, `SPLUNK_HEC_TOKEN`, `OPENROUTER_API_KEY`, `TENANT_SECRET_KEY`, `LANGSMITH_API_KEY`, `INGEST_WEBHOOK_SECRET`, `DEV_BYPASS_AUTH=1`.
3. **`/db/migrations/`** — Alembic. Initial schema present. Next: RLS hardening + audit hash chain + writeback_mode + sovereignty hybrid columns (wk-2 cleanup).
4. **`/apps/orchestrator/`** — LangGraph StateGraph + `LLMRouter` wrapper (app-side fallback) + MCP tool clients. Wks 5-8.
5. **`/apps/web/`** — Next.js investigation viewer + step-replay UI + admin panel (creds + per-role LLM config + budgets + usage). Wks 9-11.
6. **`/apps/api/`** — FastAPI; auth, tenant scoping, ingest webhook. Wk 4.
7. **`/mcp/splunk/`** — `splunk-sdk` for search + ES endpoints; `httpx` for HEC; `siem_*` tool surface. Wk 2 (skeleton) → wk 8 (writeback complete).
8. **`/evals/`** — golden-set investigation benchmarks. Splunk BOTS v3 + Atomic Red Team + honeypot + hand-labelled. Critical — this is the quality moat. Wk 6+.
9. **`/docs/compliance-mapping.md`** — Essential Eight + APRA CPS 234 claims mapped to controls. Wk 13.
10. **`/docs/design-partner-brief.pdf`** — 1-pager for MSSP outreach. Wk 12.

**Deferred until first paying customer requires it:**
- `/infra/` Terraform for AWS Sydney (ECS task defs generated from compose).
- Kubernetes manifests (maybe never; compose → ECS is enough).
- Sovereign-mode runtime: Bedrock Sydney + Azure AU East provider routes in `LLMRouter`. DB columns present from MVP.

Reuse opportunities:
- **LangGraph** for agent orchestration — native HITL `interrupt()` + Postgres checkpointer + multi-agent runway.
- **`langchain-mcp-adapters`** — bridges LangGraph node to MCP tool servers without writing per-tool glue.
- **`splunk-sdk` (PyPI)** — official, used for both search and ES endpoints via low-level `service.post()`.
- **Prompt caching** via OpenRouter passthrough — eval target wk 7. Treat 5x cost cut as hypothesis to measure, not a planning assumption.

---

## Critical risks & kill criteria

**Kill if by month 9:**
- No paid pilot converted (free pilots don't count).
- <2 MSSP conversations in active procurement.
- Microsoft ships a free sovereign Sentinel Copilot for AU gov (structural death).

**Major risks:**
1. **Founder burnout** — solo + bootstrap + 13-15wk MVP + 12mo runway. Build in 1-day-a-week protection.
2. **Sovereignty gap closes for paying tenants** — first sovereignty-sensitive AU buyer (gov-adjacent, financial services) won't accept OpenRouter+LangSmith SaaS. Sovereign-mode tier (BYO Bedrock Sydney / Azure AU East + LangSmith off + BYO keys) must be ready before that conversation closes. DB surface in MVP; runtime ships post-MVP at signal.
3. **MSSP channel conflict** — if we sell direct to mid-market AND to MSSPs serving similar segments, channel will push back. Define segmentation early.
4. **Quality gap** — Dropzone has 370% NRR because investigations are actually good. Golden-set evals from day 1.
5. **Splunk ES vs base Splunk gap** — dual writeback (`notable_update` + HEC) requires Splunk Enterprise Security. Plain Splunk Enterprise tenants get `hec_only` mode (degraded UX). Default tenant config = `hec_only` (conservative). MSSP customers with ES flip to `dual`. See ADR-0018.

---

## Verification (how we know it's working)

**Technical:**
- Golden-set of 50+ labeled Splunk incidents (Splunk BOTS v3 CTF-key-derived + Atomic Red Team + honeypot + hand-labelled ambiguous). Verdict classes: true positive, false positive, benign, inconclusive. MVP ship gate: ≥85% verdict agreement with senior analyst, ≥0.70 MITRE F1.
- Latency p50 < 5 min per investigation, p95 < 15 min.
- Audit log completeness: every LLM call (per attempt, including failures), every MCP tool call, every user action logged with hash chain integrity verifiable.

**Commercial:**
- Wks 13-15: external design partner outreach begins.
- Month 6: 1 paid pilot A$2K+/mo.
- Month 9: A$15K+ MRR, 1 MSSP reseller signed.
- Month 12: A$30K+ MRR OR clear funding path.

**Compliance:**
- Essential Eight ML2 alignment doc published wk 13.
- SOC2 Type I started month 6, attested month 9.
- IRAP assessor contacted month 9 (executed with paying government-adjacent customer).

---

## Open decisions (defer)

- Co-founder vs. solo (bootstrap-compatible either way).
- Exact MSSP partner targets (research + outreach in wk 12+).
- Sovereign-mode tier pricing model (% premium over standard tenant pricing). Defer until first sovereign-mode design-partner conversation.
