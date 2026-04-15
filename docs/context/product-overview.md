# Product Overview — Sentient Layer

**Company:** Sentient Layer (domain: `sentientlayer.ai`)
**Product:** Sovereign AI SOC triage platform.
**Working dir:** `/Users/kaya/github/cyber-ai-triage` (to be renamed as brand solidifies).

---

## One-line positioning

"The only AI SOC analyst built in Australia, for Australian compliance — running in your tenant, never leaving sovereign infrastructure."

## What we do

AI SOC analyst that ingests SIEM notable events, investigates autonomously with Claude (or configurable LLM) + MCP tools over a LangGraph state machine, and writes an OCSF Detection Finding (verdict, confidence, MITRE ATT&CK mapping, evidence chain) back to the SIEM so the human analyst sees an enriched notable inline in their existing tool.

## Wedge priorities (in order)

1. **Sovereignty** — AU data residency, no cross-border inference for paid customers; self-host path available.
2. **Compliance-native** — Essential Eight ML2 mapping, APRA CPS 234 alignment, audit-complete per-action logging, evidentiary chain-of-custody.
3. **MSSP multi-tenancy** — hard tenant isolation by month 6, channel-friendly pricing, white-label by month 9.
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

1. Compliance-native sovereignty (AU-HQ, IRAP roadmap, self-host available).
2. MSSP channel depth (hard tenant isolation, white-label, revenue share).
3. Investigation quality (prompt engineering + golden-set evals + detection-rule post-pass).
4. **Not the LLM.** Claude is an accelerant, swappable via admin panel.

## Pointers

- Strategic full-plan: `docs/PLAN.md`
- Build plan: `tasks/todo.md`
- Architecture decisions (historical): `docs/decisions/`
- Current stack locks: `docs/context/stack-locks.md`
