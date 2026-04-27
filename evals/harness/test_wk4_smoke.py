"""Wk-4/5 end-to-end smoke test.

Posts a known notable to the ingest webhook, polls Postgres until the worker
finishes Tier-1 triage. Asserts the wk-5 flow:

- `incidents.status` ∈ {'done' (auto-closed), 'triaging' (escalated),
  'inconclusive' (fallback exhausted)}.
- `investigations.verdict` ∈ {'benign', 'inconclusive'}.
- `investigations.summary` non-empty (LLM reasoning landed).
- ≥1 `usage` row with `status='success'`.
- audit chain: `incident_ingested` + `triage_started` + one of
  {`triage_auto_close`, `triage_escalated`, `triage_failed_fallback_exhausted`}.

Skipped by default (`@pytest.mark.integration`). Run on the founder's box:

    uv run pytest -m integration evals/harness/test_wk4_smoke.py
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

pytestmark = pytest.mark.integration


_DEV_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "libs"
    / "ocsf"
    / "tests"
    / "fixtures"
    / "splunk_notables"
    / "auth_failure_brute_force.json"
)


def _api_url() -> str:
    return os.environ.get("WK4_API_URL", "http://api.triage.local")


def _dsn() -> str:
    raw = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return raw.replace("postgresql+psycopg://", "postgresql://", 1)


def _secret() -> str:
    secret = os.environ.get("INGEST_WEBHOOK_SECRET", "")
    if not secret or secret.startswith("CHANGEME"):
        pytest.skip("INGEST_WEBHOOK_SECRET not set in environment")
    return secret


def _require_openrouter() -> None:
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key or key.startswith("CHANGEME"):
        pytest.skip("OPENROUTER_API_KEY not set — wk-5 triage needs live OpenRouter")


def _wait_for_completion(
    incident_id: str, *, timeout_seconds: float = 60.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    with psycopg.connect(_dsn()) as conn:
        while time.monotonic() < deadline:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT i.status, inv.id, inv.verdict, inv.summary,
                           inv.severity, inv.confidence, inv.completed_at,
                           inv.inconclusive_reason
                      FROM incidents i
                      LEFT JOIN investigations inv ON inv.incident_id = i.id
                     WHERE i.id = %s
                    """,
                    (incident_id,),
                )
                row = cur.fetchone()
            if row and row[1] is not None and row[6] is not None:
                # Investigation row exists AND has completed_at — done.
                last = {
                    "status": row[0],
                    "investigation_id": str(row[1]),
                    "verdict": row[2],
                    "summary": row[3],
                    "severity": row[4],
                    "confidence": float(row[5]) if row[5] is not None else None,
                    "inconclusive_reason": row[7],
                }
                return last
            conn.commit()
            time.sleep(0.5)
    pytest.fail(
        f"investigation for incident {incident_id} did not complete within "
        f"{timeout_seconds}s. last seen: {last}"
    )


def test_ingest_to_triage_verdict() -> None:
    _require_openrouter()
    notable = json.loads(_FIXTURE.read_text())
    payload = {"secret": _secret(), "result": notable}

    with httpx.Client(base_url=_api_url(), timeout=10.0) as client:
        response = client.post("/api/incidents/ingest", json=payload)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "accepted"
    incident_id = body["incident_id"]

    state = _wait_for_completion(incident_id)
    assert state["status"] in ("done", "triaging", "inconclusive")
    assert state["verdict"] in ("benign", "inconclusive")
    assert state["severity"] in ("info", "low", "medium", "high", "critical")
    assert state["summary"], "LLM reasoning should be populated"

    # Audit chain — at least 3 rows for the triage flow.
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT actor, action, hash_scope, length(content_hash)
              FROM audit_log
             WHERE tenant_id = %s
             ORDER BY id DESC LIMIT 6
            """,
            (_DEV_TENANT_ID,),
        )
        rows = cur.fetchall()
    actions = {r[1] for r in rows}
    assert "incident_ingested" in actions
    assert "triage_started" in actions
    assert actions & {
        "triage_auto_close",
        "triage_escalated",
        "triage_failed_fallback_exhausted",
    }
    for row in rows:
        # SHA-256 hex on every row.
        assert row[3] == 64


def test_usage_row_logged() -> None:
    """At least one `usage` row landed for the most recent investigation."""
    _require_openrouter()
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT investigation_id, role, status, attempt_num, model_requested
              FROM usage
             WHERE tenant_id = %s
             ORDER BY id DESC
             LIMIT 5
            """,
            (_DEV_TENANT_ID,),
        )
        rows = cur.fetchall()
    if not rows:
        pytest.skip(
            "no usage rows yet — run test_ingest_to_triage_verdict first or "
            "drop a notable manually"
        )
    statuses = {r[2] for r in rows}
    # At least one success — triage produced a verdict via either primary or
    # a fallback model. (A pure timeout/fallback-exhausted run wouldn't hit
    # this branch because the test would fail at the audit-chain assertion.)
    assert "success" in statuses, f"no successful triage attempt in {rows}"
    # Triage role should be present in the most recent rows.
    assert "triage" in {r[1] for r in rows}
