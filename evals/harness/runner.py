"""Eval runner — drive incidents through the live ingest path, capture results.

Mirrors `evals/harness/test_wk4_smoke.py`: posts a Splunk-shaped notable to
`/api/incidents/ingest`, polls Postgres until the investigation row's
`completed_at` is set, captures verdict + severity + MITRE techniques + cost
+ attempt history.

Why webhook (not in-process LangGraph): the runner exercises the same code
path production traffic does — webhook auth, queue dispatch, worker pickup,
checkpointer, MCP tools. Discrepancies an in-process harness would miss
(env wiring, Redis, RLS) get caught here.

Requires the compose stack up. Skips with a clear message when API or DB
isn't reachable so CI doesn't fail; smoke tests in `test_runner.py` mock
both.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import psycopg

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LabeledIncident:
    """One row from `golden.jsonl`."""

    id: str
    fixture: str
    expected_verdict: str
    expected_severity: str
    expected_techniques: list[str]
    notes: str = ""

    def load_payload(self, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
        path = repo_root / self.fixture
        loaded: dict[str, Any] = json.loads(path.read_text())
        return loaded


@dataclass(frozen=True)
class IncidentResult:
    """Captured runtime state for one incident after a run."""

    incident_id: str
    investigation_id: str | None
    runner_status: str  # "completed" | "timeout" | "ingest_failed" | "no_investigation"
    verdict: str | None
    severity: str | None
    mitre_techniques: list[str]
    confidence: int | None
    inconclusive_reason: str | None
    cost_usd: float | None
    latency_ms: int | None
    attempts: list[dict[str, Any]] = field(default_factory=list)
    fail_category: str | None = None


def load_dataset(dataset_path: Path, limit: int | None = None) -> list[LabeledIncident]:
    """Read JSONL, ignore blank lines + lines starting with `#` (comments)."""
    rows: list[LabeledIncident] = []
    with dataset_path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            rows.append(
                LabeledIncident(
                    id=obj["id"],
                    fixture=obj["fixture"],
                    expected_verdict=obj["expected_verdict"],
                    expected_severity=obj["expected_severity"],
                    expected_techniques=list(obj.get("expected_techniques", [])),
                    notes=obj.get("notes", ""),
                )
            )
            if limit is not None and len(rows) >= limit:
                break
    return rows


def post_incident(
    client: httpx.Client,
    *,
    secret: str,
    notable: dict[str, Any],
) -> str:
    """POST notable to `/api/incidents/ingest`. Returns incident_id on 202."""
    resp = client.post(
        "/api/incidents/ingest",
        json={"secret": secret, "result": notable},
    )
    resp.raise_for_status()
    body = resp.json()
    return str(body["incident_id"])


def poll_completion(
    dsn: str,
    incident_id: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any] | None:
    """Poll `investigations` row until `completed_at` is set or timeout."""
    deadline = time.monotonic() + timeout_seconds
    with psycopg.connect(dsn) as conn:
        while time.monotonic() < deadline:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT inv.id,
                           inv.verdict, inv.severity, inv.mitre_techniques,
                           inv.confidence, inv.completed_at,
                           inv.inconclusive_reason,
                           inv.total_cost_usd
                      FROM incidents i
                      LEFT JOIN investigations inv ON inv.incident_id = i.id
                     WHERE i.id = %s
                    """,
                    (incident_id,),
                )
                row = cur.fetchone()
            conn.commit()
            if row and row[0] is not None and row[5] is not None:
                return {
                    "investigation_id": str(row[0]),
                    "verdict": row[1],
                    "severity": row[2],
                    "mitre_techniques": list(row[3] or []),
                    "confidence": row[4],
                    "completed_at": row[5],
                    "inconclusive_reason": row[6],
                    "total_cost_usd": float(row[7]) if row[7] is not None else None,
                }
            time.sleep(0.5)
    return None


def fetch_attempts(dsn: str, investigation_id: str) -> list[dict[str, Any]]:
    """Per-attempt LLM ledger rows for one investigation."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT role, attempt_num, model_requested, model_used, status,
                   input_tokens, output_tokens, cost_usd, latency_ms
              FROM usage
             WHERE investigation_id = %s
             ORDER BY id ASC
            """,
            (investigation_id,),
        )
        rows = cur.fetchall()
    return [
        {
            "role": r[0],
            "attempt_num": r[1],
            "model_requested": r[2],
            "model_used": r[3],
            "status": r[4],
            "input_tokens": r[5],
            "output_tokens": r[6],
            "cost_usd": float(r[7]) if r[7] is not None else None,
            "latency_ms": r[8],
        }
        for r in rows
    ]


def _classify_failure(
    verdict: str | None,
    inconclusive_reason: str | None,
    attempts: list[dict[str, Any]],
) -> str | None:
    """Bucket a failure into one of the rubric `fail_categories`.

    Returns None when the run completed with a non-inconclusive verdict.
    Categorisation is best-effort — some failures are ambiguous and the
    bucket is a hint, not a verdict.
    """
    if verdict and verdict != "inconclusive":
        return None
    if inconclusive_reason:
        text = inconclusive_reason.lower()
        if "fallback" in text or "exhausted" in text:
            return "fallback_exhausted"
        if "timeout" in text:
            return "timeout"
        if "schema" in text or "validation" in text:
            return "schema"
        if "tool" in text:
            return "tool"
    statuses = {a["status"] for a in attempts}
    if "timeout" in statuses:
        return "timeout"
    if "validation_fail" in statuses:
        return "schema"
    return "ambiguous_label"


def run_one(
    incident: LabeledIncident,
    *,
    client: httpx.Client,
    dsn: str,
    secret: str,
    timeout_seconds: float,
    repo_root: Path = REPO_ROOT,
) -> IncidentResult:
    """Run one labeled incident through the stack, return captured result."""
    notable = incident.load_payload(repo_root)

    started_at = time.monotonic()
    try:
        incident_id = post_incident(client, secret=secret, notable=notable)
    except (httpx.HTTPError, KeyError) as exc:
        return IncidentResult(
            incident_id=incident.id,
            investigation_id=None,
            runner_status="ingest_failed",
            verdict=None,
            severity=None,
            mitre_techniques=[],
            confidence=None,
            inconclusive_reason=f"ingest error: {exc}",
            cost_usd=None,
            latency_ms=None,
            fail_category="prompt",  # treat ingest failure as a transport-layer fault
        )

    completion = poll_completion(dsn, incident_id, timeout_seconds=timeout_seconds)
    latency_ms = int((time.monotonic() - started_at) * 1000)

    if completion is None:
        return IncidentResult(
            incident_id=incident.id,
            investigation_id=None,
            runner_status="timeout",
            verdict=None,
            severity=None,
            mitre_techniques=[],
            confidence=None,
            inconclusive_reason=f"no completion in {timeout_seconds}s",
            cost_usd=None,
            latency_ms=latency_ms,
            fail_category="timeout",
        )

    inv_id = completion["investigation_id"]
    attempts = fetch_attempts(dsn, inv_id)
    fail_category = _classify_failure(
        completion["verdict"], completion["inconclusive_reason"], attempts
    )

    return IncidentResult(
        incident_id=incident.id,
        investigation_id=inv_id,
        runner_status="completed",
        verdict=completion["verdict"],
        severity=completion["severity"],
        mitre_techniques=completion["mitre_techniques"],
        confidence=completion["confidence"],
        inconclusive_reason=completion["inconclusive_reason"],
        cost_usd=completion["total_cost_usd"],
        latency_ms=latency_ms,
        attempts=attempts,
        fail_category=fail_category,
    )


def run_dataset(
    incidents: list[LabeledIncident],
    *,
    api_base: str,
    dsn: str,
    secret: str,
    timeout_seconds: float = 120.0,
    repo_root: Path = REPO_ROOT,
) -> list[IncidentResult]:
    """Loop over incidents, call run_one for each. Sequential — concurrency
    capped by tenant `max_concurrent_investigations` anyway."""
    results: list[IncidentResult] = []
    with httpx.Client(base_url=api_base, timeout=10.0) as client:
        for incident in incidents:
            result = run_one(
                incident,
                client=client,
                dsn=dsn,
                secret=secret,
                timeout_seconds=timeout_seconds,
                repo_root=repo_root,
            )
            results.append(result)
    return results


__all__ = [
    "IncidentResult",
    "LabeledIncident",
    "REPO_ROOT",
    "fetch_attempts",
    "load_dataset",
    "poll_completion",
    "post_incident",
    "run_dataset",
    "run_one",
]
