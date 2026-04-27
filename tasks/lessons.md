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

---

## Wk 2 (MCP Splunk + framework verify)

### `langchain-openai 1.1.13` warns against pointing at OpenRouter
- The `langchain-openai` 1.1.13 module + class docstrings explicitly say _"If you are pointing `base_url` at a provider such as OpenRouter, vLLM, or DeepSeek, use the corresponding provider-specific LangChain package instead (e.g., `ChatDeepSeek`, `ChatOpenRouter`)."_ Non-standard fields (`reasoning_content`, `reasoning_details`) get silently dropped.
- Wk-2 verify accepts the warning: it only needs basic-completion + tool_calls + structured-output to work, all of which the smoke harness exercises. ADR-0015's `LLMRouter` (wk 5) bypasses LangChain entirely (direct httpx → OpenRouter) for the production audit ledger, so the LangChain coupling is bounded to verify + the wk-6 graph's `bind_tools` plumbing.
- **Rule:** when `langchain-*-provider` warns about a `base_url` redirect, don't fight it — accept the warning, document the bounded blast radius, and have the production path use a thinner client. A warning means "we can't promise non-standard provider features"; if you don't need them, you don't need to switch.

### MCP transport: `streamable_http` is the spec direction; `sse` is dead
- `langchain-mcp-adapters 0.2.x` supports stdio + sse + streamable_http + websocket. `sse` is **deprecated** in MCP spec 2025-03-26. `streamable_http` (single POST endpoint, server returns plain JSON or SSE stream as needed) is the canonical replacement.
- For long-lived docker-compose MCP servers consumed by multiple containers (orchestrator + worker + replay), stdio is a non-starter (single-client) and sse is deprecated. `streamable_http` is the only correct answer.
- **Rule:** check the MCP spec deprecation status before locking transport in net-new servers. ADR-0019 captures the reasoning.

### FastMCP `BaseTool.ainvoke()` returns content-block lists, not strings
- Calling a tool through `langchain-mcp-adapters` returns the raw MCP content blocks: `[{"type": "text", "text": "...", "id": "..."}]`. NOT a plain string. Manual tool dispatch (without `ToolNode`) needs to flatten.
- **Rule:** when you bypass LangGraph's `ToolNode` and call `tool.ainvoke()` yourself, extract the text payload via `[b["text"] for b in result if b.get("type") == "text"]`. `ToolNode` does this for you in production graphs.

### splunk-sdk's exception constructors are unmockable without a stream-shaped response
- `splunklib.binding.HTTPError(response, message)` calls `response.body.read()` in `__init__` — a `bytes` body fails with `AttributeError: 'bytes' object has no attribute 'read'`. Use `io.BytesIO(b"...")` for the body field.
- `splunklib.binding.AuthenticationError(message, cause)` requires `cause` to be a real `HTTPError` instance. Use `_FakeResponse` + `HTTPError(_FakeResponse(401), "401")` first, then pass into AuthenticationError.
- **Rule:** when mocking exceptions from upstream SDKs that have non-trivial constructors, write a tiny `_FakeResponse` helper at the top of the test module rather than fighting the constructor with each test.

### mypy + multi-package workspaces collide on `tests/` module names
- Adding `apps/orchestrator/tests/__init__.py` triggered `error: Duplicate module named "tests" (also at "libs/common/tests/__init__.py")`. Same later for `conftest.py`. mypy treats relative paths as module names; identical relative paths collide.
- Two viable fixes: (a) drop `__init__.py` from test dirs (pytest doesn't need it; mypy treats them as separate namespaces); (b) `exclude` test dirs from mypy entirely. We took (b) — pytest is the test gate, mypy already type-checks every production source file.
- **Rule:** in uv workspaces, prefer namespace packages or excludes over `__init__.py`-style test packages. Don't pay strict-mode for code that isn't shipped.

### `mcp/` is a workspace dir AND `mcp` is a PyPI package — disambiguate ruff isort
- ruff's isort detection treated `from mcp import ...` as first-party because the workspace has a `mcp/` directory. Resulted in oddly grouped imports (`mcp` separated from `mcp.types`).
- Fix: `[tool.ruff.lint.isort] known-third-party = ["mcp"]`. The `mcp` PyPI package (Anthropic SDK) is third-party; the `mcp/splunk/` directory is just a path.
- **Rule:** when a workspace dir name collides with an installed package, set `known-third-party` explicitly. Same fix likely needed for any workspace dir whose name shadows a PyPI name.

### LangSmith key prefix is `lsv2_` (current), not `ls__` (legacy)
- First-pass tracing.py rejected real LangSmith keys because it only accepted `ls__` prefix. LangSmith rotated to `lsv2_` mid-2024. CLAUDE.md (and `.env.example`) inherited the stale prefix from earlier docs.
- Fix: accept both `ls__` and `lsv2_`, plus any other non-empty non-`CHANGEME_` value (covers self-hosted + Hub keys).
- **Rule:** when validating third-party API key shapes, accept multiple version prefixes — providers rotate prefixes silently. A pure prefix-match veto is brittle.

### LangChain reads `LANGCHAIN_TRACING_V2`, not `LANGSMITH_TRACING`
- First-pass `init_tracing()` checked `LANGSMITH_TRACING=true` + initialised the langsmith Client. But LangChain runnables (incl. `ChatOpenAI` + `bind_tools`) only ship traces when `LANGCHAIN_TRACING_V2=true` is in the process env. Without it, LangSmith dashboard shows no runs even though the Client constructed cleanly.
- Fix: `tracing.init_tracing()` now also `os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")` + `LANGCHAIN_PROJECT` when enabled.
- **Rule:** when wiring observability, list the env vars the *client library* reads, not just the *SDK* reads. Trace through the call path until you find the actual decision point.

### LangGraph `ainvoke({"messages": []}, config)` does NOT resume — it restarts
- Tried to test resume-after-failure by calling `verify_run` twice with the same `thread_id` + fresh `{"messages": []}` input. The second call started from START, not from the last checkpoint. The test's "resume completed" assertion was true regardless of whether `extract_ip` re-ran — so the test passed without actually proving the resume invariant.
- Fix: pass `None` as input to `graph.ainvoke(None, config)` for resume mode; supplied input means "fresh run on this thread". Wired `resume: bool = False` parameter on `verify_run`. The smoke test now also asserts `node_call_counts["extract_ip"] == 1` after both runs — proves the LLM node didn't re-fire.
- **Rule:** in LangGraph, `ainvoke(None, config)` is "resume from last checkpoint", `ainvoke(input, config)` is "fresh run with this input on this thread". Test the resume property by counting node entries, not just checking that the graph completed.

### SPL pipeline accepts `\t` and multiple spaces — token-list guards bypass
- Forbidden-SPL guard initially used a list of `"| outputlookup"` / `"|outputlookup"` literal substrings. Splunk SPL accepts arbitrary horizontal whitespace between `|` and the command name (`|\toutputlookup`, `|  outputlookup`, etc.) — none caught by the list.
- Fix: regex `r"\|\s*(outputlookup|outputcsv|...)\b"` with `re.IGNORECASE` + `\b` boundaries (so `outputlookuper` doesn't false-positive). Separate regex for `rest method=POST` (read `rest` calls remain allowed).
- **Rule:** when validating against a query language with flexible tokenisation, write a regex that matches the language's whitespace tolerance; never trust a substring list.

### MCP error-mapping ordering: `except SiemToolError: raise` must come first
- siem_query / siem_get_notable handlers wrapped Splunk SDK errors with typed `SiemToolError` subclasses. But the catch chain ended with `except Exception: raise internal(...)` — which would catch an already-typed `SiemToolError` raised by inner code (e.g. if a future refactor pushes error mapping into `_run_oneshot_sync`) and re-classify as `internal`, losing the original `kind`.
- Fix: `except SiemToolError: raise` as the first clause in every error-mapping chain. Re-raise unchanged, never re-wrap.
- **Rule:** when typed exceptions flow through a wrapping `except Exception`, always add `except <YourTypedException>: raise` first to preserve the kind. Applies anywhere you have a "rich error → generic fallback" pattern.

### OCSF `type_uid = class_uid * 100 + activity_id` — derive, don't default
- First-pass `DetectionFinding.type_uid` had a class-level default `200401` (CREATE). If a caller passed `activity_id=UPDATE` without overriding `type_uid`, the model emitted `type_uid=200401` alongside `activity_id=2` — silent OCSF inconsistency.
- Fix: `type_uid: int | None = None` + `model_validator(mode="after")` derives `class_uid * 100 + activity_id` when not supplied, validates consistency when supplied.
- **Rule:** when a field's correct value is mathematically determined by another field, derive in a model_validator. A constant default is a foot-gun the moment the dependent field changes.

### splunk-sdk `service.indexes['notable']` is a REST round-trip — cache the probe
- siem_get_notable initially called `service.indexes[name]` on every invocation to detect ES presence. `Collection.__getitem__` issues an HTTP REST call. On plain-Splunk tenants every tool call burned an extra network call to learn the index still doesn't exist.
- Fix: module-level `_notable_index_present: bool | None` cache with thread lock. Reset alongside `SplunkClientFactory.reset()` on auth failure (so a token rotation can re-detect).
- **Rule:** any "did the upstream service grow this capability?" probe should be cached for the process lifetime. Invalidate on auth-related cache resets, not on every call.

### Wk-2 founder live-gate findings (2026-04-27 run)

All 3 gates PASSED end-to-end. Several environment-specific gotchas surfaced; all are environmental, not code defects.

**Gate 1 (framework, live OpenRouter + LangSmith) — passed:**
- LangSmith API key prefix is `lsv2_pt_*` on the founder's box. Confirmed the wk-2 P0 fix to `tracing.py` (accept both `ls__` and `lsv2_`) was load-bearing — without it the key would have been silently rejected.
- LangSmith project name "cyber ai triage" (with spaces) works. URL doesn't url-encode spaces in `_langsmith_project_url`; the founder reaches the project page anyway, so no fix needed.
- One bug surfaced during the live run: `runner.py` ALSO had the stale `ls__` check (separate from `tracing.py`) in its `langsmith_enabled` summary computation. Fixed in same session — the summary was reporting `langsmith_enabled=false` while traces were actually shipping.
- **Rule:** when the same gating logic appears in two files (e.g. `tracing.init_tracing()` AND `runner.verify_run`'s summary), factor it OR keep them aligned via a single helper. Two independent copies *will* drift on the next prefix rotation.

### Splunk on founder's box uses self-signed TLS — `.env` needs `SPLUNK_VERIFY_TLS=false` for dev
- Gate 2 first attempt failed with `ssl.SSLCertVerificationError: self-signed certificate in certificate chain` because `.env` shipped `SPLUNK_VERIFY_TLS=true` (the conservative production default).
- The Splunk Enterprise install on the founder's box (192.168.0.x, Splunk 10.0.2 on Ubuntu) uses Splunk's default self-signed cert. Production tenants will have proper CA-signed certs.
- Fix at the env level: set `SPLUNK_VERIFY_TLS=false` in the founder's local `.env` (it's gitignored — won't leak to prod). The compose file passes the env through to mcp-splunk; same setting works for the container.
- **Rule:** for any third-party service with self-signed dev certs, the local `.env` must override the production-strict default. Document in `docs/splunk-setup.md` so future onboarders don't hit this.

### Splunk 10.0.2 rejects `earliest_time='-100y'` — use bounded windows
- Initial `splunk_smoke.py` + integration tests used `earliest_time="-100y"` to "widen the window" past BOTS v3's 2018 dates. Splunk 10.0.2 returns `HTTP 400 — "Invalid earliest_time"`.
- Fix: use sensible recent windows (`-1h` for `_internal`/live data) or absolute timestamps for BOTS v3 (`2018-08-01T00:00:00`).
- **Rule:** "absurdly wide" time windows aren't a portable trick across Splunk versions. Pin to either a recent window (live data) or absolute timestamps (historic data sets).

### BOTS v3 was NOT actually loaded on founder's box — wk-1 lesson was wrong
- `tasks/todo.md` wk-1 review claimed BOTS v3 was loaded per `docs/splunk-setup.md` §6. Gate 2 confirmed: `index=botsv3` doesn't exist; `main` has 12M live UniFi events; `windows_security` has 299k current Win events.
- Wk-1 documentation passed for the load step; the actual load command was apparently never run (or loaded into the wrong indexes).
- Impact: wk-2 integration tests that depend on BOTS data skip cleanly (the test file's `pytest.skip` paths trigger). Wk-5 eval golden set requires BOTS — must be loaded before then.
- Fix: founder runs `docs/splunk-setup.md` §6 BOTS load command before wk 5. Updated integration test names + skip messages so the dependency is unambiguous (`test_botsv3_*` → "load BOTS v3 or stay skipped"). Added a BOTS-independent smoke (`test_internal_basic_query`) so the integration suite has a guaranteed-pass baseline.
- **Rule:** "documented load step" ≠ "loaded data". Verify with a real query against the index before declaring a data-load task done.

### Gate 3 (docker tools-loaded smoke) passed cleanly
- `docker compose build mcp-splunk` succeeded (deps changed from FastAPI to FastMCP + splunk-sdk).
- `mcp-splunk` came up healthy in 5 seconds; `/health` returns 200; `splunk_smoke --invoke` runs `siem_query` against `index=_internal | head 5` end-to-end through the container.
- Confirms the full path: host langchain-mcp-adapters → docker network :8080 → FastMCP `/mcp` → splunk-sdk → Splunk LAN box → response → SiemQueryOutput → MCP content block back to host.
- No issues surfaced — transport choice (ADR-0019) + `streamable_http` + Pydantic schema serialisation all integrated cleanly.

---

## Wk 3 (OCSF normalization layer)

### `incidents.raw_payload_s3_key` + `incidents.ocsf_normalized` already existed — read schema before planning a migration
- `tasks/todo.md` wk-3 brief said "Store raw + OCSF-normalized payloads in `incidents` table — `raw_payload_s3_key` (MinIO) + `ocsf_normalized` JSONB. Migration likely needs a NOT-NULL guard on `ocsf_normalized` after backfill." Both columns already shipped in the initial migration `81e2d43b3ec0_initial_schema.py` (lines 95–96). Plan agent caught this on a `grep` pass; the original brief was written from a stale read.
- **Rule:** before scoping an Alembic migration in a plan, grep `db/migrations/versions/` for the target column names. Existing-but-forgotten columns are common in early-stage repos because the initial schema lands speculatively ahead of the consumer code.

### `MitreTechnique` validator only enforces alphabetic-leading + non-empty — it does NOT filter T-codes
- Plan agent initially proposed reusing `MitreTechnique`'s `_normalize_technique_uid` validator (`detection_finding.py:185`) to filter Splunk's `annotations.mitre_attack` strings. Re-read showed it only rejects empty / non-alphabetic-leading. Tactic codes (`TA0002`) and free text (`foo`) would have constructed bogus `MitreTechnique` rows instead of being silently dropped.
- Fix: mapper-side regex `^T\d+(\.\d+)?$` BEFORE constructing the model. Two dedicated tests pin this (`test_tactic_code_filtered`, `test_non_tcode_filtered`).
- **Rule:** when a plan says "filter via existing validator X", read X. Validators are usually tighter on shape than semantics; semantic filtering belongs at the call site that knows domain rules.

### Defer storage helpers until the bytes-to-key contract has a caller
- `libs/common/storage.py` (MinIO upload helper) was tempting to ship in wk 3 alongside the mapper. Resisted. Wk-4 ingest webhook owns the bytes-to-key contract (key naming convention, content-hash dedup, error handling on MinIO down) — designing it in wk 3 with no caller would have meant guessing the contract.
- **Rule:** infrastructure helpers should be designed by their first caller, not pre-built ahead of one. Plan to ship them with the consumer week.

### Sub-model surface: add only what realistic input shape forces
- `DetectionFinding` extension added `User`, `Actor`, `NetworkEndpoint` (forced by every realistic Splunk notable having `user` / `src_ip` / `dest_ip`). Deferred `Device`, `File`, `Process`, `Evidences[]`, `Enrichments[]` to wk-6 when the investigation agent's enrichment pipeline forces them.
- **Rule:** new schema surface has a maintenance cost (model + tests + serialisation paths + `to_hec_dict` namespacing). Delay until a concrete consumer needs each field.

### Pydantic v2 reserves leading-underscore field names — alias Splunk's `_time` / `_raw`
- Splunk notables ship `_time` (epoch) and `_raw` (full event text). Pydantic v2 raises if you declare model fields starting with underscore. Solution: declare as `notable_time: float | str = Field(..., alias="_time")` + `model_config = ConfigDict(populate_by_name=True, extra="allow")`.
- **Rule:** for any Pydantic v2 model that mirrors an external JSON shape, scan for leading-underscore field names up front and alias them. `populate_by_name=True` is needed if any internal code constructs by attribute name rather than by alias.

---

## Wk 7 (Tier-2 completeness + review + caching)

### `_validate_with_retry` schema-retry HTTP call is uncosted — gap predates wk-7
- LLMRouter's schema-retry path inside `_validate_with_retry` calls `_traced_call` a second time WITHOUT a corresponding `log_usage_attempt` row. That second call's tokens + cost are absent from both the `usage` ledger AND the wk-7 per-investigation accumulator. Wk-7 inherits the gap; the cap can underestimate spend by one call worth of tokens.
- Why not fix in wk-7: the retry response object is consumed for parsed output; bolting `log_usage_attempt` onto it requires plumbing `attempt_num` semantics (does the retry get its own `attempt_num`? sub-attempt? same?) and changes the per-attempt ledger contract that ADR-0015 documents. Better to fix in wk-12 hardening with an ADR amendment than smuggle in mid-feature work.
- **Rule:** when a feature build (cap accumulator) discovers a pre-existing audit/ledger gap, document the gap with code comment + lessons entry + carry-over in `tasks/todo.md`. Don't expand scope mid-week.

### Reuse existing columns before adding new ones
- Wk-7 plan initial draft proposed a new `evidence_manifest_s3_key` column on `investigations`. Pressure-test caught: `evidence_s3_key` and `review_notes` were already on the initial schema (lines 116, 118 of `81e2d43b3ec0`). Migration shrank to: 3 totals + `review_status` + `review_metadata` + `tenants.per_investigation_token_cap`.
- **Rule:** before drafting a migration, grep the initial schema for every column name in scope. The wk-1/2 migrations land speculatively; columns sit unused until the consumer arrives, and a fresh week tends to forget they exist.

### Anthropic `cache_control` is content-block-level, not message-level
- First plan draft routed cache markers as a top-level kwarg / message-metadata. Anthropic-via-OpenRouter actually requires `cache_control` to attach to a content **block** inside the message (`content: [{"type":"text","text":"...","cache_control":{"type":"ephemeral"}}]`). String content must be rewritten to a 1-block array before the wire send.
- Implementation: a `cacheable: bool` flag on the message dict (content-stable across LangGraph state appends) consumed by `call_chat_completion._apply_cache_markers`. Index-based `cache_breakpoints: list[int]` is wrong because the messages list grows over the agent loop.
- Anthropic enforces max 4 cache breakpoints per request (system + finding + MITRE = 3 today).
- **Rule:** for any provider-specific wire feature (cache_control, structured output, tool_choice variants), confirm WHERE in the request shape it lives BEFORE designing the API surface. "It's a message metadata field" is wrong for Anthropic; it's a content-block field.

### Review-role failures must be best-effort, not propagating
- `review_node` failure inside the LangGraph (FallbackChainExhausted, BudgetExceeded, unhandled) does NOT fail the investigation. The verdict is already drafted; review is annotation. Skip with `status='skipped'` + `review_skipped` audit + log.
- Why this matters: review hits the same per-investigation cap as `plan/agent/correlate/draft_verdict`. A near-cap investigation that scrapes through draft_verdict but blows the cap on review would wrongly mark the whole investigation `inconclusive` if review propagated — destroying the verdict that already cost real tokens.
- **Rule:** any "after the verdict" annotation step (review, manifest upload, evidence-row writeback) must be wrapped so its failure doesn't roll back the verdict + audit chain that already committed.

### Sensitive-field leaks travel through more than one channel — close ALL of them
- Wk-7 round-1 fix #5 stripped cap config from `BudgetExceeded.__str__`. Round-2 review caught that `runner.py`'s exception handler manually rebuilt the same cap leak in `error_message` and passed it to `_finalize_inconclusive` → `emit_investigation_failed` → `audit_log.details.error_message`. The fix moved the leak from `str(exc)` to a structured field; didn't close it.
- The structured `emit_budget_exceeded` audit row was already the right channel for cap details. The runner's manual reconstruction in `error_message` was redundant + leaky.
- **Rule:** when fixing a "this field leaks" bug, grep every callsite that consumes the structured exception attributes (`exc.cap_usd`, `exc.total_cost_usd`, etc.) — not just `str(exc)`. The fix is incomplete until every interpolation of those attributes into a customer-eventually-visible surface is closed.

### Defend cost-accumulator UPDATEs against Byzantine inputs at SQL time
- Wk-7 round-2 fix R-3: `update_investigation_totals` initially used `COALESCE(:val, 0)` for NULL safety. A response with negative `prompt_tokens` (compromised proxy / malformed JSON / future bug) would have DECREMENTED running totals and defeated the per-investigation cap gate. The cap silently disables in that scenario.
- Fix: wrap each accumulator value in `COALESCE(GREATEST(:val, 0), 0)`. Clamps negatives to zero AT WRITE TIME — Python-side validation can be bypassed by future callers; SQL-side clamp is the load-bearing invariant.
- **Rule:** any monotonic counter UPDATE (cost, tokens, attempt count) where the increment comes from external/network input must clamp at the SQL layer. Trust the database, not the caller.

### Speed-running tests creates dead `or True` no-op assertions
- Wk-7 round-2 fix R-4: `test_investigation_manifest.py` had `assert ("uploaded", upload_kwargs) or True  # exists check below` — the `or True` makes it always pass; the comment refers to a different downstream assertion. The `upload_kwargs` variable was captured but never asserted on.
- Pattern: rushing tests sometimes leaves "TODO-shaped" placeholders that look like assertions but aren't.
- **Rule:** review every `assert` line in new tests for tautology. `assert X or True`, `assert X or 1`, `assert isinstance(X, object)`, `assert X is not None or True` — all silently always-pass. If the assertion is hard to write, leave a `# TODO` and skip it explicitly with `pytest.xfail` so it surfaces in CI.
