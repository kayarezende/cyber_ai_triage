# Product Overview — Sentient Layer

**Company:** Sentient Layer (domain: `sentientlayer.ai`)
**Product:** Australian-built AI SOC triage platform. Sovereignty-roadmapped (post-MVP paid tier).
**Working dir:** `/Users/kaya/github/cyber-ai-triage` (to be renamed as brand solidifies).

---

## One-line positioning

"Australian-built AI SOC analyst — Splunk-first, OCSF-native, audit-complete."

A separately-priced **sovereign-mode tier** ships post-MVP for sovereignty-sensitive tenants (BYO Bedrock Sydney / Azure AU East routing, LangSmith disabled, customer-supplied LLM keys). MVP is **not sovereign** — routes through OpenRouter (US) + LangSmith SaaS. The DB surface for sovereign-mode is in place from MVP day 1 (per ADR-0016) so activation is a feature flag, not a migration.

## What we do

AI SOC analyst that ingests SIEM notable events, investigates autonomously with Claude (or configurable LLM via OpenRouter) + MCP tools over a LangGraph state machine, and writes an OCSF Detection Finding (verdict, confidence, MITRE ATT&CK mapping, evidence chain) back to the SIEM so the human analyst sees an enriched notable inline in their existing tool (when Splunk ES is installed; otherwise verdict surfaces in Sentient Layer UI only — see ADR-0018).

## Wedge priorities (in order)

1. **Australian-built** — AU support, AU pricing, AU customer-success ownership. Sovereignty path via the post-MVP sovereign-mode tier (ADR-0016).
2. **Compliance-native** — Essential Eight ML2 mapping, APRA CPS 234 alignment, hash-chained audit log (ADR-0017), evidentiary chain-of-custody.
3. **MSSP multi-tenancy** — soft isolation MVP, hard tenant isolation by month 6, channel-friendly pricing, white-label by month 9.
4. **SIEM-agnostic** — Splunk first (MVP), Sentinel wk 10-14, CrowdStrike/Defender XDR month 6+. Generic MCP tool names mean agent prompts don't change per SIEM.

## ICP prioritization

**Primary:** Tier-2/3 AU MSSPs — Sekuro, Content Security, Shearwater, Triskele Labs, Bitwise, Gridware, Jaarvis.
**Secondary:** AU mid-market direct (100-1000 employees, non-regulated).
**Not MVP:** CyberCX / Telstra Purple / Tier-1 MSSPs (9-12mo procurement kills bootstrap); US mid-market (Dropzone owns); consumer (graveyard economics).

## What we are NOT

- Not a SIEM. We plug into Splunk/Sentinel, not replace them.
- Not a SOAR. We output recommended actions; humans or existing SOAR execute.
- Not an auto-response system in MVP. Every containment action is analyst-approved via LangGraph `interrupt()`.
- Not a foundation model. Claude/Gemini are accelerants, not the moat.
- Not pursuing Kubernetes, Terraform, service mesh, or IRAP PROTECTED in MVP.

## Go-to-market snapshot (12-month bootstrap)

- Months 0-3: Ship MVP. Founder = design partner #0 on his own Splunk box.
- Months 3-6: 1-2 paid AU MSSP or mid-market pilots.
- Months 6-9: 2-3 MSSP reseller/co-sell agreements; SOC2 Type I.
- Months 9-12: Bootstrap break-even (~A$30K MRR solo) OR traction-justified US seed.

## Competitive moat (in order)

1. Australian-built + compliance-native (AU-HQ, IRAP-roadmapped, sovereign-mode tier post-MVP).
2. MSSP channel depth (hard tenant isolation month 6, white-label month 9, revenue share).
3. Investigation quality (prompt engineering + golden-set evals + detection-rule post-pass + per-attempt audit ledger).
4. **Not the LLM.** Claude/Gemini are accelerants, swappable via admin panel per role config.

## Pointers

- Strategic full-plan: `docs/PLAN.md`
- Build plan: `tasks/todo.md`
- Architecture decisions (historical): `docs/decisions/`
- Current stack locks: `docs/context/stack-locks.md`
