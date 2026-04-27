"""Wk-4 end-to-end smoke test.

Runs against a live `docker compose up` stack with seeded dev tenant + MinIO
bucket. Posts a known notable, polls Postgres until the worker's stub
investigation row appears.

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


def _wait_for_investigation(
    incident_id: str, *, timeout_seconds: float = 15.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    with psycopg.connect(_dsn()) as conn:
        while time.monotonic() < deadline:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT i.status, inv.id, inv.verdict, inv.summary,
                           inv.severity, inv.confidence
                      FROM incidents i
                      LEFT JOIN investigations inv ON inv.incident_id = i.id
                     WHERE i.id = %s
                    """,
                    (incident_id,),
                )
                row = cur.fetchone()
            if row and row[1] is not None:
                last = {
                    "status": row[0],
                    "investigation_id": str(row[1]),
                    "verdict": row[2],
                    "summary": row[3],
                    "severity": row[4],
                    "confidence": float(row[5]),
                }
                return last
            conn.commit()
            time.sleep(0.5)
    pytest.fail(
        f"investigation row for incident {incident_id} did not appear within "
        f"{timeout_seconds}s. last seen: {last}"
    )


def test_wk4_ingest_to_stub_verdict() -> None:
    notable = json.loads(_FIXTURE.read_text())
    payload = {"secret": _secret(), "result": notable}

    with httpx.Client(base_url=_api_url(), timeout=10.0) as client:
        response = client.post("/api/incidents/ingest", json=payload)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "accepted"
    incident_id = body["incident_id"]

    state = _wait_for_investigation(incident_id)
    assert state["status"] == "done"
    assert state["verdict"] == "inconclusive"
    assert state["severity"] == "info"
    assert state["confidence"] == 0.0
    assert "wk-4 stub" in state["summary"]

    # Audit chain — at least 2 rows for this flow (incident_ingested +
    # stub_investigation_completed).
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT actor, action, hash_scope, length(content_hash)
              FROM audit_log
             WHERE tenant_id = %s
             ORDER BY id DESC LIMIT 4
            """,
            (_DEV_TENANT_ID,),
        )
        rows = cur.fetchall()
    actions = [r[1] for r in rows]
    assert "incident_ingested" in actions
    assert "stub_investigation_completed" in actions
    # SHA-256 hex = 64 chars on every row.
    for row in rows:
        assert row[3] == 64
