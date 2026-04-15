# Sentient Layer

Sovereign AI SOC triage platform for Australian MSSPs + mid-market. SIEM-agnostic, Splunk-first MVP.

- **Domain:** `sentientlayer.ai`
- **Strategic plan:** [`docs/PLAN.md`](docs/PLAN.md)
- **Build plan (wk 0-15):** [`tasks/todo.md`](tasks/todo.md)
- **Locked decisions:** [`CLAUDE.md`](CLAUDE.md)
- **Architecture Decision Records:** [`docs/decisions/`](docs/decisions/)

## Status

Scaffolding in progress. See `tasks/todo.md` for week-by-week milestones.

## Prerequisites

- Docker Desktop (with Compose v2)
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Node.js 20+ + npm (for `apps/web`)
- Remote Splunk Enterprise box reachable over LAN/VPN
  - Management REST on port `8089`
  - HEC on port `8088`
  - Service account token + HEC token provisioned
- API keys (obtain before wk 2):
  - OpenRouter (LLM routing)
  - LangSmith (agent tracing)
  - Optionally Anthropic (direct, escape hatch)

## Quickstart

```bash
# 1. Configure environment
cp .env.example .env
# Generate Fernet key into .env:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Then edit .env: TENANT_SECRET_KEY, SPLUNK_*, OPENROUTER_API_KEY, LANGSMITH_API_KEY

# 2. Add local hostnames (one-time)
sudo sh -c 'echo "127.0.0.1 app.triage.local api.triage.local" >> /etc/hosts'

# 3. Install Python deps (host-side, for migrations + seeds)
uv sync --all-packages

# 4. Bring up the full stack
docker compose up -d --build

# 5. Run database migrations (from host, against the compose postgres)
uv run alembic upgrade head

# 6. Create LangGraph checkpointer tables (not Alembic-managed)
uv run python db/seeds/setup_checkpointer.py

# 7. Seed MITRE ATT&CK techniques
uv run python db/seeds/seed_mitre.py

# 8. Verify
curl http://api.triage.local/health   # → {"status":"ok","service":"api"}
curl -I http://app.triage.local/      # → 200 OK
docker compose ps                     # → every service healthy
```

> **Note:** Alembic manages the app schema. The 4 LangGraph checkpointer tables
> (`checkpoint_migrations`, `checkpoints`, `checkpoint_blobs`, `checkpoint_writes`)
> are created by `langgraph-checkpoint-postgres` via `setup_checkpointer.py` —
> they are **not** managed by Alembic.

> **TLS:** Traefik serves HTTP only in MVP local dev. TLS hardening (self-signed
> cert or internal CA + `/etc/hosts` + app.triage.local trust) lands wk 12.

## Layout

```
apps/
  api/              # FastAPI REST/webhook layer
  orchestrator/     # LangGraph agent runner
  worker/           # Redis queue consumer
  web/              # Next.js 15 + Tailwind frontend
mcp/
  splunk/           # MCP server exposing generic siem_* tools backed by Splunk
libs/
  ocsf/             # OCSF 1.3.0 schema + mappers
db/
  migrations/       # Alembic
  seeds/            # MITRE STIX + checkpointer setup
evals/
  harness/          # Eval runner
  datasets/         # Splunk BOTS v3 + Atomic Red Team + honeypot
  rubrics/          # Scoring rubrics
docs/
  PLAN.md           # Strategic plan
  context/          # Current-state snapshots
  decisions/        # 14 ADRs
tasks/
  todo.md           # Week-by-week build plan (master tracker)
  lessons.md        # Self-improvement notes
```

## Reading order for a new contributor

1. [`docs/context/product-overview.md`](docs/context/product-overview.md) — what Sentient Layer is.
2. [`docs/context/stack-locks.md`](docs/context/stack-locks.md) — current architectural commitments.
3. [`docs/decisions/README.md`](docs/decisions/README.md) — ADR index.
4. [`tasks/todo.md`](tasks/todo.md) — what's next to build.
