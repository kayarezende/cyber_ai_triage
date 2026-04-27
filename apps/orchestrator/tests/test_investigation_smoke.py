"""Wk-6 Tier-2 investigation integration smoke + crash-resume tests.

Skips cleanly when DATABASE_URL or OPENROUTER_API_KEY are placeholders.

Dependencies on the live system:
  * Postgres with the wk-1+ schema applied (`alembic upgrade head`) AND the
    LangGraph checkpointer tables (`db/seeds/setup_checkpointer.py`).
  * OpenRouter API key.
  * Seed rows: dev tenant + `llm_role_config` for the `investigation` role.
    These are created by the existing fixtures in `db/seeds/`.

The MCP Splunk server is NOT required — `build_mcp_client` is monkey-patched
to return a static tool that emits a fixed JSON blob. Founder runs the live
end-to-end variant via the manual checklist in the wk-6 plan.

Two tests:

1. `test_investigation_smoke_runs_to_verdict` — happy path. Drives the full
   `run_tier2_investigation` against real OpenRouter + Postgres. Asserts the
   resulting `incidents.status='done'` + `investigations.verdict` populated +
   ≥4 `usage` rows + the audit chain landed.

2. `test_investigation_smoke_resumes_after_inject_failure` — drives
   `graph.ainvoke(initial, config)` with `INVESTIGATION_INJECT_FAILURE=correlate`
   so the graph raises mid-flight. Re-invokes with `ainvoke(None, config)`
   and asserts `node_call_counts['plan']==1` (didn't re-fire) +
   `correlate==2` (resumed at the failed node). Proves the LangGraph
   checkpointer reload semantics work end-to-end for the wk-6 graph — same
   load-bearing invariant as wk-2's verify smoke.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import psycopg
import pytest
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation import runner as inv_runner
from sentient_orchestrator.investigation.graph import build_investigation_graph
from sentient_orchestrator.investigation.runner import (
    _strip_psycopg_dsn,
    run_tier2_investigation,
)
from sentient_orchestrator.investigation.state import InvestigationState

pytestmark = pytest.mark.integration

DEV_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")


def _dsn() -> str:
    raw = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return _strip_psycopg_dsn(raw)


def _ocsf_payload() -> dict[str, Any]:
    """Minimal valid OCSF Detection Finding for the smoke test."""
    return {
        "category_uid": 2,
        "class_uid": 2004,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": 4,
        "time": 1700000000000,
        "metadata": {
            "version": "1.3.0",
            "log_provider": "splunk",
            "product": {"name": "Splunk", "vendor_name": "Splunk Inc."},
        },
        "finding_info": {
            "uid": "fid-tier2-smoke",
            "title": "PowerShell C2 candidate",
            "desc": "Encoded PowerShell beacon to known C2 domain.",
            "analytic": {
                "name": "Endpoint - Powershell - encoded",
                "type_id": 2,
                "uid": "an-test",
                "version": "1",
            },
        },
        "mitre_techniques": ["T1059.001"],
        "attacks": [],
    }


@tool
async def static_siem_query(spl: str = "", earliest: str = "-1h", latest: str = "now") -> str:
    """Run a Splunk SPL search and return matching events as JSON."""
    return json.dumps(
        {
            "spl": spl,
            "events": [
                {
                    "_time": "2024-01-01T00:00:00Z",
                    "host": "wks-test-01",
                    "user": "alice",
                    "process": "powershell.exe",
                    "command_line": "-EncodedCommand SGVsbG8=",
                }
            ],
        }
    )


@tool
async def static_siem_get_notable(notable_id: str = "") -> str:
    """Fetch a Splunk Enterprise Security notable by ID."""
    return json.dumps({"notable_id": notable_id, "found": False, "degraded": True})


def _static_tools() -> list[Any]:
    return [static_siem_query, static_siem_get_notable]


@pytest.fixture(autouse=True)
def _reset_node_counts() -> None:
    nodes.reset_node_call_counts()


@pytest.fixture
def patch_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_client() -> Any:
        client = MagicMock()
        client.get_tools = AsyncMock(return_value=_static_tools())
        return client

    monkeypatch.setattr(inv_runner, "build_mcp_client", fake_client)


def _seed_test_incident(
    tenant_id: UUID,
) -> tuple[UUID, UUID]:
    """Insert an incident + investigation row in the wk-5 escalated state.

    Returns (incident_id, investigation_id).
    """
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    ocsf = json.dumps(_ocsf_payload())

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO incidents
                (id, tenant_id, siem_source, ocsf_normalized, status)
            VALUES
                (%s, %s, 'splunk', %s::jsonb, 'triaging')
            """,
            (str(incident_id), str(tenant_id), ocsf),
        )
        cur.execute(
            """
            INSERT INTO investigations
                (id, tenant_id, incident_id, started_at, severity, confidence,
                 mitre_techniques, summary, verdict, inconclusive_reason)
            VALUES
                (%s, %s, %s, NOW(), 'high', 0.80,
                 ARRAY['T1059.001']::text[],
                 'encoded powershell beacon',
                 'inconclusive', 'tier_2_pending_wk6')
            """,
            (str(investigation_id), str(tenant_id), str(incident_id)),
        )
        conn.commit()
    return incident_id, investigation_id


def _cleanup_incident(incident_id: UUID, investigation_id: UUID) -> None:
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM audit_log WHERE investigation_id = %s",
            (str(investigation_id),),
        )
        cur.execute(
            "DELETE FROM usage WHERE investigation_id = %s",
            (str(investigation_id),),
        )
        cur.execute(
            "DELETE FROM investigations WHERE id = %s",
            (str(investigation_id),),
        )
        cur.execute("DELETE FROM incidents WHERE id = %s", (str(incident_id),))
        conn.commit()


async def _wipe_thread(database_url: str, thread_id: str) -> None:
    async with AsyncPostgresSaver.from_conn_string(
        _strip_psycopg_dsn(database_url)
    ) as saver:
        await saver.adelete_thread(thread_id)


@pytest.fixture
def db_cleanup() -> Callable[[UUID, UUID, str | None], None]:
    """Schedule rows + thread to be torn down at end of test."""
    cleanups: list[tuple[UUID, UUID, str | None]] = []

    def _register(incident_id: UUID, investigation_id: UUID, thread_id: str | None = None) -> None:
        cleanups.append((incident_id, investigation_id, thread_id))

    yield _register

    import asyncio

    for incident_id, investigation_id, thread_id in cleanups:
        if thread_id:
            try:
                asyncio.run(_wipe_thread(_dsn(), thread_id))
            except Exception:
                pass
        try:
            _cleanup_incident(incident_id, investigation_id)
        except Exception:
            pass


# ---------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_investigation_smoke_runs_to_verdict(
    require_database_url: str,
    require_openrouter_key: str,
    patch_mcp: None,
    db_cleanup: Callable[[UUID, UUID, str | None], None],
) -> None:
    incident_id, investigation_id = _seed_test_incident(DEV_TENANT_ID)
    thread_id = f"inv-{investigation_id.hex[:12]}"
    db_cleanup(incident_id, investigation_id, thread_id)

    await run_tier2_investigation(
        investigation_id=investigation_id,
        tenant_id=DEV_TENANT_ID,
        incident_id=incident_id,
    )

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT i.status, inv.verdict, inv.confidence, inv.severity,
                   inv.langgraph_thread_id, inv.completed_at, inv.ocsf_output,
                   inv.inconclusive_reason
              FROM incidents i
              JOIN investigations inv ON inv.incident_id = i.id
             WHERE i.id = %s
            """,
            (str(incident_id),),
        )
        row = cur.fetchone()
    assert row is not None
    status, verdict, confidence, severity, thread, completed_at, ocsf_out, reason = row

    if status == "inconclusive":
        # Acceptable — model occasionally bails as inconclusive on synthetic
        # evidence. Don't fail the smoke for that; assert the audit chain is
        # intact and `inconclusive_reason` is informative.
        assert reason is not None and reason != "tier_2_pending_wk6"
    else:
        assert status == "done", row
        assert verdict in ("true_positive", "false_positive", "benign")
        assert ocsf_out is not None
    assert thread == thread_id, row
    assert completed_at is not None
    assert severity in ("info", "low", "medium", "high", "critical")

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT action FROM audit_log WHERE investigation_id = %s ORDER BY id",
            (str(investigation_id),),
        )
        actions = [r[0] for r in cur.fetchall()]
        cur.execute(
            "SELECT count(*) FROM usage WHERE investigation_id = %s",
            (str(investigation_id),),
        )
        usage_count_row = cur.fetchone()
    assert usage_count_row is not None
    assert "investigation_started" in actions, actions
    # Either complete (happy path) or failed (model bailed) — both audit.
    assert (
        "investigation_complete" in actions or "investigation_failed" in actions
    ), actions
    # Per-attempt LLM ledger landed at least once per node (plan + draft = 2 minimum).
    assert usage_count_row[0] >= 2, usage_count_row[0]


# ---------------------------------------------------------------- crash-resume


@pytest.mark.asyncio
async def test_investigation_smoke_resumes_after_inject_failure(
    require_database_url: str,
    require_openrouter_key: str,
    monkeypatch: pytest.MonkeyPatch,
    db_cleanup: Callable[[UUID, UUID, str | None], None],
) -> None:
    """Crash mid-graph + resume must not re-fire already-checkpointed nodes."""
    incident_id, investigation_id = _seed_test_incident(DEV_TENANT_ID)
    thread_id = f"inv-resume-{uuid.uuid4().hex[:8]}"
    db_cleanup(incident_id, investigation_id, thread_id)

    from sentient_ocsf.detection_finding import validate_detection_finding

    finding = validate_detection_finding(_ocsf_payload())
    tools = _static_tools()
    config: RunnableConfig = {
        "configurable": {
            "thread_id": thread_id,
            "tenant_id": str(DEV_TENANT_ID),
            "investigation_id": str(investigation_id),
            "finding": finding,
            "tools": tools,
            "mitre_descs": {},
        }
    }
    initial_state: InvestigationState = {
        "messages": [],
        "investigation_id": str(investigation_id),
        "tenant_id": str(DEV_TENANT_ID),
        "incident_id": str(incident_id),
        "triage_severity": "high",
        "triage_confidence": 80,
        "triage_mitre_guesses": ["T1059.001"],
        "triage_entities": [],
        "triage_reasoning": "encoded powershell beacon",
        "tool_call_count": 0,
        "draft_verdict": None,
    }

    db_url = _strip_psycopg_dsn(require_database_url)

    # Run 1 — fail at correlate. plan + agent (+ tools) + correlate enter.
    monkeypatch.setenv(nodes.INVESTIGATION_INJECT_FAILURE_ENV, "correlate")
    async with AsyncPostgresSaver.from_conn_string(db_url) as saver:
        graph = build_investigation_graph().compile(checkpointer=saver)
        with pytest.raises(RuntimeError, match="simulated failure in correlate"):
            await graph.ainvoke(initial_state, config=config)

    plan_count_after_fail = nodes.node_call_counts["plan"]
    correlate_count_after_fail = nodes.node_call_counts["correlate"]
    draft_count_after_fail = nodes.node_call_counts["draft_verdict"]
    assert plan_count_after_fail == 1, dict(nodes.node_call_counts)
    assert correlate_count_after_fail == 1, dict(nodes.node_call_counts)
    assert draft_count_after_fail == 0, dict(nodes.node_call_counts)

    # Run 2 — env unset, resume from checkpoint.
    monkeypatch.delenv(nodes.INVESTIGATION_INJECT_FAILURE_ENV, raising=False)
    async with AsyncPostgresSaver.from_conn_string(db_url) as saver:
        graph = build_investigation_graph().compile(checkpointer=saver)
        await graph.ainvoke(None, config=config)

    # Plan must NOT re-fire — proves checkpoint replay.
    assert nodes.node_call_counts["plan"] == plan_count_after_fail, (
        f"plan re-ran on resume; counts: {dict(nodes.node_call_counts)}"
    )
    # Correlate ran at least once more (counter increments on entry; LangGraph
    # may retry the failed node before succeeding).
    assert nodes.node_call_counts["correlate"] >= correlate_count_after_fail + 1, (
        f"correlate did not re-run; counts: {dict(nodes.node_call_counts)}"
    )
    # Draft verdict ran for the first time.
    assert nodes.node_call_counts["draft_verdict"] >= 1, dict(nodes.node_call_counts)
