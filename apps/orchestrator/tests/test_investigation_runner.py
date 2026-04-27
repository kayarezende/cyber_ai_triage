"""Unit tests for the Tier-2 investigation runner.

Mocks tenant_session + AsyncPostgresSaver + build_mcp_client + the compiled
graph so the runner's claim/finalize SQL + audit emissions can be exercised
without a live DB or MCP server. Real end-to-end coverage lives in
`test_investigation_smoke.py` (Day 5).
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import runner as runner_mod
from sentient_orchestrator.investigation.runner import (
    _make_thread_id,
    _pg_text_array,
    _strip_psycopg_dsn,
    run_tier2_investigation,
)
from sentient_orchestrator.investigation.state import InvestigationOutput
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INCIDENT = UUID("22222222-2222-2222-2222-222222222222")
INV = UUID("33333333-3333-3333-3333-333333333333")


def _ocsf_payload() -> dict[str, Any]:
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
            "uid": "fid-tier2",
            "title": "Suspicious PS",
            "analytic": {
                "name": "ps analytic",
                "type_id": 2,
                "uid": "an-1",
                "version": "1",
            },
        },
        "mitre_techniques": [],
        "attacks": [],
    }


class _Result:
    def __init__(
        self,
        *,
        first: tuple[Any, ...] | None = None,
        rowcount: int = 0,
    ) -> None:
        self._first = first
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return self._first


class _FakeConn:
    """Records execute() calls + serves the SELECT stubs."""

    def __init__(
        self,
        *,
        triage_row: tuple[Any, ...] | None = (
            "high",  # severity
            0.80,  # confidence (NUMERIC stored as Decimal in real DB)
            ["T1059.001"],
            "encoded powershell beacon",
            "tier_2_pending_wk6",
        ),
        ocsf_payload: dict[str, Any] | None = None,
        claim_rowcount: int = 1,
    ) -> None:
        self._triage_row = triage_row
        self._ocsf = ocsf_payload if ocsf_payload is not None else _ocsf_payload()
        self._claim_rowcount = claim_rowcount
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        if "FROM investigations" in sql and "inconclusive_reason" in sql and "SELECT" in sql:
            return _Result(first=self._triage_row)
        if "SELECT ocsf_normalized FROM incidents" in sql:
            return _Result(first=(self._ocsf,))
        if "FROM mitre_techniques" in sql:
            return _Result(first=None)
        if "UPDATE incidents SET status = 'investigating'" in sql:
            return _Result(rowcount=self._claim_rowcount)
        return _Result(rowcount=1)


@pytest.fixture
def fake_conn() -> _FakeConn:
    return _FakeConn()


@pytest.fixture
def patch_session(
    monkeypatch: pytest.MonkeyPatch, fake_conn: _FakeConn
) -> _FakeConn:
    @contextmanager
    def session(_tid: UUID) -> Any:
        yield fake_conn

    monkeypatch.setattr(runner_mod, "tenant_session", session)
    return fake_conn


@pytest.fixture
def audit_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            calls.append((name, kwargs))

        return _f

    monkeypatch.setattr(
        runner_mod, "emit_investigation_started", _track("started")
    )
    monkeypatch.setattr(
        runner_mod, "emit_investigation_complete", _track("complete")
    )
    monkeypatch.setattr(
        runner_mod, "emit_investigation_failed", _track("failed")
    )
    return calls


@pytest.fixture
def patch_mcp(monkeypatch: pytest.MonkeyPatch) -> list[MagicMock]:
    tools: list[MagicMock] = [
        MagicMock(name="siem_query"),
        MagicMock(name="siem_get_notable"),
    ]

    def fake_client() -> Any:
        client = MagicMock()
        client.get_tools = AsyncMock(return_value=tools)
        return client

    monkeypatch.setattr(runner_mod, "build_mcp_client", fake_client)
    return tools


@pytest.fixture
def patch_checkpointer(monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def fake_saver(_dsn: str) -> Any:
        yield MagicMock()

    fake_class = MagicMock()
    fake_class.from_conn_string = fake_saver
    monkeypatch.setattr(runner_mod, "AsyncPostgresSaver", fake_class)


@pytest.fixture
def patch_graph(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace build_investigation_graph with a stub whose compile().ainvoke returns a verdict."""
    captured: dict[str, Any] = {"final_state": None}

    class _Graph:
        async def ainvoke(self, _state: Any, config: Any = None) -> dict[str, Any]:
            captured["last_config"] = config
            assert captured["final_state"] is not None
            return captured["final_state"]

    class _Builder:
        def compile(self, *, checkpointer: Any) -> _Graph:
            captured["checkpointer"] = checkpointer
            return _Graph()

    monkeypatch.setattr(runner_mod, "build_investigation_graph", lambda: _Builder())
    return captured


@pytest.fixture
def patch_mitre(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner_mod, "fetch_technique_descriptions", lambda _conn, _ids: {}
    )


@pytest.fixture
def env_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:p@h:5432/db"
    )


# ---------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_run_tier2_happy_path(
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_graph: dict[str, Any],
    patch_mitre: None,
    env_db: None,
) -> None:
    verdict = InvestigationOutput(
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1059.001"],
        summary="PowerShell C2.",
        evidence=["spl: index=main proc=powershell"],
        reasoning="confirmed encoded payloads",
    )
    patch_graph["final_state"] = {"draft_verdict": verdict.model_dump()}

    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )

    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'investigating'" in sql_blob
    assert "SET status = 'done'" in sql_blob
    assert "ocsf_output" in sql_blob

    # Verdict serialized to ocsf_output JSONB column.
    update_calls = [
        params for sql, params in patch_session.queries
        if "ocsf_output" in sql
    ]
    assert any(
        json.loads(p["ocsf"])["verdict"] == "true_positive" for p in update_calls
    )

    audit_actions = [name for name, _ in audit_calls]
    assert "started" in audit_actions
    assert "complete" in audit_actions
    assert "failed" not in audit_actions


@pytest.mark.asyncio
async def test_passes_finding_and_tools_via_config(
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_graph: dict[str, Any],
    patch_mitre: None,
    env_db: None,
) -> None:
    patch_graph["final_state"] = {
        "draft_verdict": InvestigationOutput(
            verdict="benign",
            confidence=70,
            severity="low",
            mitre_techniques=[],
            summary="x",
            evidence=[],
            reasoning="r",
        ).model_dump()
    }
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    cfg = patch_graph["last_config"]["configurable"]
    assert cfg["thread_id"].startswith("inv-")
    assert cfg["tenant_id"] == str(TENANT)
    assert cfg["investigation_id"] == str(INV)
    # Tools loaded from MCP and threaded through config.
    assert cfg["tools"] == patch_mcp


# ---------------------------------------------------------------- claim guard


@pytest.mark.asyncio
async def test_skips_when_already_claimed(
    monkeypatch: pytest.MonkeyPatch,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_graph: dict[str, Any],
    patch_mitre: None,
    env_db: None,
) -> None:
    # Race: another worker already flipped status to 'investigating'.
    fake = _FakeConn(claim_rowcount=0)

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield fake

    monkeypatch.setattr(runner_mod, "tenant_session", session)
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    # No started/complete/failed audit emitted — early return before audit.
    assert audit_calls == []


@pytest.mark.asyncio
async def test_skips_when_not_pending_tier2(
    monkeypatch: pytest.MonkeyPatch,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mitre: None,
    env_db: None,
) -> None:
    """`inconclusive_reason != 'tier_2_pending_wk6'` → skip (already finalized)."""
    fake = _FakeConn(
        triage_row=("high", 0.8, [], "x", None),  # cleared inconclusive_reason
    )

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield fake

    monkeypatch.setattr(runner_mod, "tenant_session", session)
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    assert audit_calls == []


# ---------------------------------------------------------------- failure paths


@pytest.mark.asyncio
async def test_fallback_exhausted_finalizes_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_mitre: None,
    env_db: None,
) -> None:
    class _Graph:
        async def ainvoke(self, *_a: Any, **_kw: Any) -> dict[str, Any]:
            raise FallbackChainExhausted(role="investigation", attempts=["a", "b"])

    class _Builder:
        def compile(self, **_kw: Any) -> _Graph:
            return _Graph()

    monkeypatch.setattr(runner_mod, "build_investigation_graph", lambda: _Builder())

    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )

    sql_blob = " ".join(q[0] for q in patch_session.queries)
    assert "SET status = 'inconclusive'" in sql_blob
    failed = [k for n, k in audit_calls if n == "failed"]
    assert failed
    assert failed[0]["error_type"] == "FallbackChainExhausted"
    assert failed[0]["reason"] == "fallback_chain_exhausted"


@pytest.mark.asyncio
async def test_unhandled_exception_finalizes_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_mitre: None,
    env_db: None,
) -> None:
    class _Graph:
        async def ainvoke(self, *_a: Any, **_kw: Any) -> dict[str, Any]:
            msg = "splunk down"
            raise RuntimeError(msg)

    class _Builder:
        def compile(self, **_kw: Any) -> _Graph:
            return _Graph()

    monkeypatch.setattr(runner_mod, "build_investigation_graph", lambda: _Builder())
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    failed = [k for n, k in audit_calls if n == "failed"]
    assert failed
    assert failed[0]["error_type"] == "RuntimeError"
    assert failed[0]["reason"] == "graph_unhandled_exception"


@pytest.mark.asyncio
async def test_missing_database_url_finalizes_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mitre: None,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    failed = [k for n, k in audit_calls if n == "failed"]
    assert failed
    assert failed[0]["reason"] == "config_missing_database_url"


@pytest.mark.asyncio
async def test_missing_verdict_finalizes_inconclusive(
    patch_session: _FakeConn,
    audit_calls: list[tuple[str, dict[str, Any]]],
    patch_mcp: list[MagicMock],
    patch_checkpointer: None,
    patch_graph: dict[str, Any],
    patch_mitre: None,
    env_db: None,
) -> None:
    """Graph completes but draft_verdict slot is empty → inconclusive."""
    patch_graph["final_state"] = {"draft_verdict": None}
    await run_tier2_investigation(
        investigation_id=INV, tenant_id=TENANT, incident_id=INCIDENT
    )
    failed = [k for n, k in audit_calls if n == "failed"]
    assert failed
    assert failed[0]["reason"] == "no_verdict_emitted"


# ---------------------------------------------------------------- helpers


def test_pg_text_array() -> None:
    assert _pg_text_array([]) == "{}"
    assert _pg_text_array(["T1059"]) == "{T1059}"
    assert _pg_text_array(["T1059", "T1071.004"]) == "{T1059,T1071.004}"


def test_make_thread_id_starts_with_inv() -> None:
    tid = _make_thread_id(INV)
    assert tid.startswith("inv-")
    # Hex-prefix length: "inv-" + 12 chars.
    assert len(tid) == len("inv-") + 12


def test_strip_psycopg_dsn() -> None:
    assert (
        _strip_psycopg_dsn("postgresql+psycopg://u:p@h:5432/db")
        == "postgresql://u:p@h:5432/db"
    )
    # No-op on already-stripped form.
    assert (
        _strip_psycopg_dsn("postgresql://u:p@h:5432/db")
        == "postgresql://u:p@h:5432/db"
    )
