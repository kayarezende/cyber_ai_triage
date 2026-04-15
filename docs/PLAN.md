# Plan: Sovereign AI SOC Triage for Australian MSSP + Mid-Market

## Context

**The problem.** AU orgs drown in SIEM/EDR alerts. ISC2 2025: 95% report material skills gaps; SOC analysts burn out (70% of juniors quit <3yr). Microsoft/Omdia 2026: 46% of alerts are false positives. IBM 2025: global avg breach cost USD 4.44M. Regulatory pressure climbing: SOCI Act, APRA CPS 234/230, Essential Eight ML2 mandatory for 98 Commonwealth entities, Privacy Act penalties up to A$50M. Post-Optus/Medibank, AU buyers want sovereignty.

**Why now.** AI SOC category is at Gartner's Peak of Inflated Expectations (2025) — category real, already commoditizing. Dropzone ($37M B, 11x ARR), Prophet ($30M A), 7AI ($130M A, largest cyber A in history) have US enterprise. **No credible AU-HQ AI SOC product exists.** Microsoft Security Copilot is free with M365 E5 — existential threat to horizontal US-facing plays, non-threat to sovereign AU MSSP channel.

**Why this founder.** SOC operator + AI/ML engineer = rare wedge. Can build MVP solo or lean, sell credibly to MSSPs, bootstrap under 12 months.

**Intended outcome.** Within 12 months, 2-3 paid AU MSSP pilots + 1-2 direct AU mid-market customers on Microsoft Sentinel AI triage agent, with compliance-native posture (Essential Eight-aligned, data sovereign, audit-complete) positioned to win sovereignty-sensitive deals US vendors can't serve.

---

## Strategy

### Positioning
**"The only AI SOC analyst built in Australia, for Australian compliance — running in your tenant, never leaving sovereign infrastructure."**

Wedge stack (in priority):
1. **Sovereignty** — AU data residency, no cross-border inference, model hosted in AWS Sydney or Azure Australia East (IRAP-certified regions).
2. **Compliance-native** — Essential Eight ML2 mapping, APRA CPS 234 alignment, audit-complete per-action logging, evidentiary chain-of-custody for post-incident review.
3. **MSSP multi-tenancy** — hard tenant isolation from day 1, channel-friendly pricing, white-label option by month 9.
4. **Microsoft Sentinel-first** — dominant AU stack, aligns with E8 ML2, largest deployed footprint in Commonwealth and large enterprise.

### What we are NOT doing
- Not competing horizontally with Dropzone on US mid-market. They've won that race.
- Not chasing CrowdStrike/Palo Alto/Google stacks at MVP — breadth kills bootstrap timelines.
- Not doing consumer. Research shows graveyard economics.
- Not pursuing IRAP PROTECTED certification in year 1 (A$150-300K + 6-9mo). Design for it; pursue with first paying government-adjacent customer co-funding.
- Not selling to Tier-1 MSSPs (CyberCX, Telstra Purple) in year 1 — 9-12mo procurement kills bootstrap.

### ICP prioritization
**Primary: Tier-2/3 AU MSSPs** — Sekuro, Content Security, Shearwater, Triskele Labs, Bitwise, Gridware, Jaarvis. These need differentiation vs. CyberCX, have faster decision cycles, will co-build, and bring compounding customer exposure.
**Secondary: AU mid-market direct (100-1000 employees, non-regulated)** — faster close, smaller ACV, generates case studies for MSSP sales, covers runway.

---

## Product (MVP scope)

### Core: Microsoft Sentinel AI triage agent
Input: Sentinel incident (via Graph Security API or Logic App webhook).
Output: decision-ready investigation report (verdict, confidence, evidence chain, suggested actions, MITRE ATT&CK mapping).

**MVP capabilities (ship in 12 weeks):**
1. **Ingest & enrich** — pull incident + entities (IPs, users, hosts, files) from Sentinel. Enrich with KQL queries against the customer's Sentinel workspace, plus public threat intel (VirusTotal, AbuseIPDB, GreyNoise free tiers initially).
2. **Autonomous investigation** — agent plans investigation (LLM reasoner) → runs KQL + API queries (MCP-style tools) → correlates → produces verdict.
3. **Evidence & audit** — every tool call, query, LLM prompt/response logged immutably. Exportable as forensic timeline.
4. **Human-in-loop** — all actions gated. No auto-response in MVP. Analyst approves or rejects.
5. **MSSP multi-tenancy** — per-customer workspace isolation, per-customer model routing, hard data boundaries.

**Deferred (post-MVP):**
- CrowdStrike Falcon connector (month 6)
- Microsoft Defender XDR alerts (month 4 — same Graph API)
- Phishing/BEC specialized flow (month 7)
- Auto-response / containment (month 9, opt-in)
- White-label branding (month 9)

---

## Architecture (Docker Compose first, cloud later)

**Deployment model for MVP**: everything runs in Docker Compose. Single `docker-compose.yml` brings up the whole stack on a laptop or any VM. No cloud lock-in, no infra cost, no Terraform yet. Same containers later deploy to AWS Sydney (ECS/Fargate) or customer's own infra — which is itself a selling point for sovereignty-conscious buyers who want self-host.

**Containers (services in docker-compose.yml):**
- `orchestrator` — Python, LangGraph StateGraph + `langchain-mcp-adapters` + MCP tool clients. Stateful via Postgres checkpointer; HITL via `interrupt()`. Handles investigation planning + execution.
- `web` — Next.js frontend. Investigation viewer, tenant admin, audit log explorer.
- `api` — Thin REST/GraphQL layer between `web` and `orchestrator`. Auth, tenant scoping, rate limiting.
- `postgres` — tenants, users, investigation metadata, audit log index.
- `redis` — job queue (investigations are async), prompt cache keys, rate limits.
- `minio` — S3-compatible object store for audit logs, investigation artifacts, evidence bundles. Swap to real S3 + Object Lock in production.
- `mcp-sentinel` — MCP server wrapping Microsoft Graph + Sentinel KQL. Isolated container per tenant via compose profiles in dev; in prod, process-level isolation.
- `mcp-enrich` — MCP server for VirusTotal / AbuseIPDB / GreyNoise.
- `worker` — background investigation runner pulling jobs from redis.
- `traefik` or `caddy` — reverse proxy, TLS termination for local hostnames.

**Stack:**
- **LLM**: Anthropic Claude (Opus 4.6 for investigation reasoning, Haiku 4.5 for triage classification). Prompt caching aggressively — multi-turn investigations cache-hit the incident context. No customer data to OpenAI (positioning + Anthropic has AU data residency roadmap).
- **Hosting**: Docker Compose locally and on a single VPS/EC2 for pilot customers. Migrate to AWS Sydney (ap-southeast-2, IRAP-assessed) when first customer requires it — same containers, ECS task definitions generated from the compose file.
- **Data**: Customer Sentinel data stays in customer's tenant. We orchestrate via Graph API from our control plane. We store only: investigation metadata, audit logs, our own prompts/responses. Encrypted at rest (Postgres pgcrypto + MinIO SSE).
- **Agent framework**: LangGraph + `langchain-anthropic` + `langchain-mcp-adapters` + `langgraph-checkpoint-postgres`. Chosen for native HITL `interrupt()`, resumable investigations via Postgres checkpointer, and multi-agent runway for month 6+ specialists.
- **Frontend**: Next.js + Tailwind.
- **Auth**: Entra ID SSO + SCIM (required by enterprise customers).
- **Compliance primitives from day 1**: per-tenant encryption keys, append-only audit log table (Postgres + MinIO Object Lock equivalent), SOC2 controls wired, Essential Eight mapping doc.

**Why Docker Compose is the right bootstrap call:**
- Zero cloud cost during 12-month runway. Runs on founder's laptop or a A$20/mo Hetzner box for demos.
- Customers who want self-host get it for free — strong sovereignty story ("we ship you a compose file, your data never leaves your walls").
- Easy path to production: compose → AWS ECS (via `ecs-cli compose` or manual task defs), compose → customer-hosted, compose → airgapped. Same artifacts.
- Single-command onboarding for design partners: `git clone && docker compose up`.

**What we're NOT building:**
- Our own foundation model. Claude is the accelerant, not the moat.
- A SIEM. We plug into Sentinel, not replace it.
- A SOAR. We output recommended actions; humans or existing SOAR (Tines/Torq/Sentinel playbooks) execute.
- Kubernetes, Terraform, service mesh, or anything else that burns weeks before product-market fit.

---

## Go-to-market (12-month bootstrap)

### Months 0-3: Build + design partners
- Ship MVP (Sentinel alert → investigation report).
- Recruit **3 unpaid design partners**: 1 Tier-2/3 MSSP, 2 mid-market AU companies (leverage founder's network).
- Weekly feedback loop. Ship fixes in days.
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
- LLM inference: ~A$200-800/mo per mid-size tenant (1K-5K alerts/mo triaged, prompt caching on), dropping ~10x/yr per Epoch AI.
- AWS infra: ~A$150-300/mo per tenant.
- Total COGS: **A$350-1,100/mo**. Gross margin at A$2K pricing: 45-82%. Improves fast.

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

## Key files & next steps (when ExitPlanMode approved)

This is greenfield; no existing code. Bootstrap order:
1. **/README.md** — one-page spec + `docker compose up` quickstart.
2. **/docker-compose.yml** — all services (orchestrator, web, api, postgres, redis, minio, mcp-sentinel, mcp-enrich, worker, traefik).
3. **/docker-compose.override.yml** — dev-only overrides (hot reload, exposed ports, seed data).
4. **/.env.example** — required env vars (ANTHROPIC_API_KEY, Entra tenant IDs, VT key, etc.).
5. **/docs/compliance-mapping.md** — Essential Eight + APRA CPS 234 claims mapped to controls.
6. **/apps/orchestrator/** (Python) — LangGraph StateGraph + MCP tool clients.
7. **/apps/web/** — Next.js investigation viewer + audit log explorer.
8. **/apps/api/** — thin REST layer (auth, tenant scoping, rate limiting).
9. **/mcp/sentinel/** — MCP server wrapping Microsoft Graph + Sentinel KQL.
10. **/mcp/enrich/** — MCP server for VT / AbuseIPDB / GreyNoise.
11. **/evals/** — golden-set investigation benchmarks. Critical — this is the quality moat.
12. **/docs/design-partner-brief.pdf** — 1-pager for MSSP outreach.

**Deferred until first paying customer requires it:**
- `/infra/` Terraform for AWS Sydney (ECS task defs generated from compose).
- Kubernetes manifests (maybe never; compose → ECS is enough).

Reuse opportunities:
- **LangGraph** for agent orchestration — native HITL + checkpointing + production track record in SOC/security space.
- MCP servers for Microsoft Graph / Sentinel — likely community MCP already exists; check `modelcontextprotocol` repos.
- **Prompt caching** in Claude API — investigation prompts cache the incident context, cutting costs 5-10x on multi-turn.

---

## Critical risks & kill criteria

**Kill if by month 9:**
- No paid pilot converted (free pilots don't count).
- <2 MSSP conversations in active procurement.
- Microsoft ships a free sovereign Sentinel Copilot for AU gov (structural death).

**Major risks:**
1. **Founder burnout** — solo + bootstrap + 12mo. Build in 1-day-a-week protection.
2. **Data residency for Claude** — if Anthropic doesn't offer AU residency by month 6, either self-host open-weight fallback (Llama/Qwen on Bedrock Sydney) or get contractual data-processing addendum. Research now.
3. **MSSP channel conflict** — if we sell direct to mid-market AND to MSSPs serving similar segments, channel will push back. Define segmentation early.
4. **Quality gap** — Dropzone has 370% NRR because investigations are actually good. Golden-set evals from day 1.

---

## Verification (how we know it's working)

**Technical:**
- Golden-set of 50 labeled Sentinel incidents (true positive, false positive, benign, critical). MVP must hit ≥85% verdict agreement with senior analyst.
- Latency <5 min per investigation at p50, <15 min at p95.
- Audit log completeness: every LLM call, every KQL query, every tool call traceable.

**Commercial:**
- Month 3: 3 design partners using weekly.
- Month 6: 1 paid pilot A$2K+/mo.
- Month 9: A$15K+ MRR, 1 MSSP reseller signed.
- Month 12: A$30K+ MRR OR clear funding path.

**Compliance:**
- Essential Eight ML2 alignment doc published month 3.
- SOC2 Type I started month 6, attested month 9.
- IRAP assessor contacted month 9 (executed with paying government-adjacent customer).

---

## Open decisions (defer)

- Company name / domain.
- Co-founder or solo (bootstrap-compatible either way).
- Anthropic vs. Bedrock Claude routing (depends on AU residency timeline).
- Exact MSSP partner targets (research + outreach in month 1).
