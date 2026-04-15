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

---

## Wk 1 (scaffolding)

### Don't ask AskUserQuestion on obvious approach calls — commit to the rec
- In plan mode I surfaced three clarifications (TLS posture, MCP stub transport, commit layout) all with strong "Recommended" defaults. User rejected the question tool: "plan it out again" — they wanted me to lock the recs in the plan, not ask.
- **Rule:** if a plan choice has an objectively stronger default (friction, reversibility, scope), bake it in as a *Locked decision* section. Reserve AskUserQuestion for genuinely close calls or missing domain context the user has and I don't.

### Verify Docker Desktop socket path + default-socket setting before wiring Docker providers
- Traefik's Docker provider failed on user's macOS setup because the Docker context points to `~/.docker/run/docker.sock`, not `/var/run/docker.sock`. Even after fixing the mount path, Docker Desktop's socket proxy still returned empty error bodies to Traefik's streaming endpoint. Lost ~30 min debugging post-launch.
- **Rule:** for any container that needs the Docker socket on macOS, up front (a) add `DOCKER_SOCKET` env override defaulting to `/var/run/docker.sock`, (b) tell the user to either enable Docker Desktop → Settings → Advanced → "Allow the default Docker socket to be used", or (c) use `tecnativa/docker-socket-proxy` sidecar.

### Host-port collisions: don't default to :3000 / :8000 / :5432 in dev overrides
- Web on `3000:3000` failed: user had another node process (a "Skateboard Game") bound to host :3000. Remapped to 3001.
- **Rule:** when adding host-port exposes for dev convenience, pick odd ports (3001, 8001, 5433) or document the conflict risk. Users' dev machines carry history.

### Stubs should be stub-shaped, not aspirational
- Initial orchestrator/worker stubs had no healthcheck signal — compose would mark them unhealthy or need `disable: true`. Added a `touch /tmp/ready` heartbeat + `stat -c %Y` mtime-staleness check. Simple + honest: crashes actually flip unhealthy within ~90s.
- **Rule:** a stub that's going to sit in compose for weeks needs a real liveness signal. Don't rely on "the process hasn't exited" — that's a lie once the main loop crashes silently.

### `package = false` in uv workspace means the src isn't importable
- Initial apps were `[tool.uv] package = false` (matching session-1 style). At import time: `ModuleNotFoundError: sentient_api`. Flipped all five members to real hatchling build-backends so `uv sync` installs them as editable workspace packages.
- **Rule:** `tool.uv.package = false` is for *virtual* members (dep-only, no code). Any workspace member with source to import from elsewhere needs a real build-backend (hatchling is cheapest).

### Alembic versions dir is generated + immutable — exclude from ruff
- Ran `ruff check .` for the first time in session 2 and got 8 errors, all in `db/migrations/versions/81e2d43b3ec0_initial_schema.py` (typing.Union style, E501 on SQL string literals). Fixing them would mean rewriting a landed migration.
- **Rule:** add `extend-exclude = ["db/migrations/versions"]` to `[tool.ruff]` at the same time as first Alembic migration. Don't chase lint on machine-generated immutable files.
