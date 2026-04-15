# Lessons

Self-improvement notes per global CLAUDE.md. Update after corrections from user.

---

## Planning phase (pre wk 1)

### Don't assume prior decisions are user-stated when they may be AI-inferred
- I asserted a "no LangChain" veto that the user did not actually state — it had been written into the original plan document as an assumption. User corrected: "I don't know what you're talking about."
- **Rule:** when memory/planning docs record a decision, note whether it was user-stated or AI-inferred. Never cite an inferred preference as a user veto.

### Correct wrong premises, accept correct decisions
- User said "Python for API layer because it scales to thousands of logs a second" — the scale premise is wrong (Node handles that fine; also we ingest incidents, not raw logs). But the decision (Python everywhere for solo-dev cognitive load) is correct.
- **Rule:** when a user gives a correct decision for a wrong reason, separate the two. Acknowledge the decision, correct the premise briefly, move on. Don't silently accept wrong premises; don't sycophantically agree with everything.

### Verify technical claims instead of asserting from memory
- I over-claimed that `splunk-sdk-python` doesn't do `notable_update` cleanly. Verified via context7 docs — the SDK low-level `service.post(path)` handles it fine with session auth reuse. Correction was forced by user asking "are you sure?"
- **Rule:** for load-bearing technical claims (library capabilities, API support, feature matrices), verify via current docs before asserting. If uncertain, say so explicitly and offer to verify.

### Don't commit architecture that depends on incompatible abstractions
- Initially locked "Claude Agent SDK + OpenRouter + MCP" — but Claude Agent SDK is Claude-only and does not route through OpenRouter. Found this only during critical review. Would have broken wk 2 implementation.
- **Rule:** when locking framework + routing decisions, verify the combination is coherent BEFORE locking. Don't trust that two good choices compose.

### Surface hidden scope honestly
- Initially planned 12 weeks solo for MVP. Real scope (admin panel, review role, HITL rules engine, dual writeback, per-role LLM config, full test suite, docs/ADR structure) requires 13+2 weeks. Told user up-front rather than pretend 12 is achievable.
- **Rule:** when user-requested features expand scope, re-estimate and surface honestly. Don't pretend the original timeline still works.

### Load Splunk BOTS v3 in wk 1, not wk 10
- Early plan had eval dataset load in wk 10. User caught it implicitly by asking "what data does the agent actually use during dev?" Agent cannot be prompt-tuned (wk 5-8) without real data; loading BOTS in wk 10 is too late.
- **Rule:** for any dev-dependency (data, test fixtures, external service credentials), schedule in wk 1. Late arrival blocks implementation weeks.

### Generic abstraction layer pays off when multiple implementations are imminent
- User was right to insist on `siem_*` generic MCP tool names from wk 1 rather than Splunk-specific. Sentinel + CrowdStrike + Defender XDR are all in the roadmap. Retrofitting abstraction later is expensive; designing it in is cheap.
- **Rule:** when a plugin point has ≥3 known future implementations, design the abstraction up front.

### When user pushes back, actually reconsider — don't just re-present the same rec
- User asked "why not LangChain over LangGraph?" I gave a fair comparison (LangChain's own team deprecated old agent APIs in favor of LangGraph). Then user asked "do a careful comparison between LangGraph and Pydantic AI" — didn't just re-recommend, gave honest per-dimension scorecard. Good outcome: user picked informed.
- **Rule:** when user pushes back on a recommendation, assume my framing missed something. Re-do the comparison from scratch, include trade-offs even against my own rec.

### "Best" is context-dependent; don't cave to "is it the best?"
- User asked "LangGraph is the best option, right?" Temptation is to sycophantically agree. Better: acknowledge LangGraph is the right call for this product's specific needs (HITL + checkpointing + SOC production track record) but not universally best.
- **Rule:** validate the decision with specific-case reasoning, not generic "yes it's the best."
