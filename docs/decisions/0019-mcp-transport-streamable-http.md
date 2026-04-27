# 0019: MCP transport — `streamable_http` for the Splunk MCP server

Date: 2026-04-27
Status: Accepted

## Context

Wk 2 of the Sentient Layer MVP build replaces the `mcp/splunk` `/health`-only FastAPI stub with a real MCP server exposing `siem_query` + `siem_get_notable` (the wk-2 surface; full surface lands wks 6 + 8). The Anthropic MCP spec defines three transports for client/server communication:

| Transport | Description | Spec status |
|---|---|---|
| `stdio` | Server runs as a subprocess of the client; stdin/stdout JSON-RPC | Stable, supported |
| `sse` | HTTP + Server-Sent Events streaming | **Deprecated** in MCP spec 2025-03-26 |
| `streamable_http` | Single HTTP endpoint, server returns plain JSON or SSE stream as needed | Current canonical HTTP transport (replaces `sse`) |

The Sentient Layer architecture has the MCP Splunk server as a long-lived docker-compose service (`mcp-splunk`) consumed by the orchestrator and (from wk 4) the worker — eventually also a replay/eval harness and the wk-9 web UI's "time-travel" stepper. Multi-client access from inside the docker network is the steady-state assumption.

## Decision

**Lock `streamable_http` as the MCP transport for all SIEM MCP servers** — Splunk wk 2, Sentinel wk 10–14, future SIEMs (CrowdStrike, Defender XDR) post-MVP.

Concretely the Splunk MCP server uses `mcp.server.fastmcp.FastMCP` (>=1.27 for `streamable_http_app`):

```python
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("sentient-siem-splunk")

@mcp.custom_route("/health", methods=["GET"])
async def health(_): ...

app = mcp.streamable_http_app()  # uvicorn target
```

Clients (orchestrator) connect via `langchain-mcp-adapters >=0.2`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StreamableHttpConnection

client = MultiServerMCPClient({
    "splunk": StreamableHttpConnection(
        transport="streamable_http",
        url="http://mcp-splunk:8080/mcp",
    )
})
tools = await client.get_tools()
```

The `/mcp` endpoint and the `/health` route co-host on the same Starlette ASGI app via FastMCP's `custom_route` decorator — no parent FastAPI wrapper. The Dockerfile healthcheck (`curl -fsS http://localhost:8080/health`) keeps working unchanged.

**Wk-2 verification (PASSED 2026-04-27):** `apps/orchestrator/src/sentient_orchestrator/verify/splunk_smoke.py` round-trips empty + tools-loaded servers via `streamable_http`. Protocol version 2025-11-25 negotiated. `langchain-mcp-adapters` 0.2.2 ↔ FastMCP 1.27.0 confirmed compatible.

## Alternatives considered

- **`stdio`**. Single-client semantics — the parent process owns the subprocess pipe. Breaks the moment the orchestrator AND worker AND replay-harness need to talk to the same Splunk MCP server. Also makes "long-lived docker-compose service" awkward (would need a thin daemon-spawning wrapper). Rejected.
- **`sse`**. Works for our topology, but deprecated in MCP spec 2025-03-26 in favour of `streamable_http`. Building net-new on a deprecated transport is a known accruing tech-debt cost. Rejected.
- **gRPC + custom MCP-over-gRPC layer**. Theoretically faster + better backpressure than HTTP. Not part of the MCP spec; would fork us off `langchain-mcp-adapters` interop. Rejected — premature optimization.
- **No transport at all (in-process Python imports of tool functions)**. Tightly couples the agent runtime to the Splunk client deps. Loses the SIEM-agnostic abstraction (ADR-0002): swapping in a Sentinel MCP server in wk 10–14 would mean refactoring imports vs. flipping a connection URL. Rejected.

## Consequences

**Gain:**
- Multi-client by default — orchestrator, worker, replay tooling, future eval harness can all share one server.
- Forward-compatible with the MCP spec's HTTP direction; `sse` deprecation doesn't bite us.
- Same transport for the wk-10 Sentinel connector → reuse the orchestrator's `MultiServerMCPClient` config shape verbatim.
- `/mcp` + `/health` co-host cleanly via `@mcp.custom_route` — no FastAPI wrapper needed.

**Accept:**
- HTTP overhead per tool call vs. stdio. Acceptable inside the docker network; per-call latency dominated by Splunk search time anyway.
- Auth surface — wk 2 has none (relies on docker-network isolation). When the MCP server crosses the host boundary (wk 11/12 hardening), we add a shared-secret bearer header, layered via Traefik or in-app via FastMCP middleware.
- `mcp[cli]>=1.27` floor — older versions lack `streamable_http_app` + `custom_route`. Pinned.

## Related

- ADR-0002 — Splunk-first, SIEM-agnostic MCP abstraction (transport choice doesn't leak to the agent's tool surface; this ADR is purely how clients reach the server).
- ADR-0014 — Shared-secret webhook auth (mirror this pattern for MCP-layer auth when needed).
- `mcp/splunk/src/sentient_mcp_splunk/main.py` — FastMCP wiring.
- `apps/orchestrator/src/sentient_orchestrator/verify/splunk_smoke.py` — transport gate harness.
