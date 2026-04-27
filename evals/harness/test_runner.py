"""Unit tests for the eval runner — mocks httpx + psycopg, no live stack."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx

from evals.harness.runner import (
    LabeledIncident,
    _classify_failure,
    fetch_attempts,
    load_dataset,
    poll_completion,
    post_incident,
    run_one,
)

# ---- load_dataset


def test_load_dataset_skips_blanks_and_comments(tmp_path: Path) -> None:
    raw = (
        '\n'
        '# this is a comment line\n'
        '{"id":"a","fixture":"x.json","expected_verdict":"benign","expected_severity":"info"}\n'
        '\n'
        '{"id":"b","fixture":"y.json","expected_verdict":"true_positive","expected_severity":"high","expected_techniques":["T1110"],"notes":"hi"}\n'
    )
    path = tmp_path / "ds.jsonl"
    path.write_text(raw)
    rows = load_dataset(path)
    assert [r.id for r in rows] == ["a", "b"]
    assert rows[1].expected_techniques == ["T1110"]
    assert rows[1].notes == "hi"
    assert rows[0].expected_techniques == []  # default


def test_load_dataset_respects_limit(tmp_path: Path) -> None:
    rows_in = [
        {"id": str(i), "fixture": "x", "expected_verdict": "benign", "expected_severity": "info"}
        for i in range(5)
    ]
    path = tmp_path / "ds.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows_in))
    rows = load_dataset(path, limit=3)
    assert len(rows) == 3


# ---- post_incident


def test_post_incident_returns_id_on_202() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 202
    response.json.return_value = {"incident_id": "abc-123", "status": "accepted"}
    response.raise_for_status.return_value = None
    client = MagicMock()
    client.post.return_value = response

    incident_id = post_incident(client, secret="s", notable={"x": 1})
    assert incident_id == "abc-123"
    client.post.assert_called_once_with(
        "/api/incidents/ingest",
        json={"secret": "s", "result": {"x": 1}},
    )


# ---- poll_completion


@contextmanager
def _mock_psycopg_connect(rows_sequence: list[Any]):
    """Yield a context manager whose cursor returns rows from the sequence
    one fetchone() at a time. Used to simulate poll iterations."""
    cur = MagicMock()
    cur.fetchone.side_effect = rows_sequence
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with patch("evals.harness.runner.psycopg.connect", return_value=conn):
        yield conn


def test_poll_completion_returns_when_completed_at_set() -> None:
    completed_row = (
        "inv-1", "true_positive", "high", ["T1110"],
        85, "2026-04-30T00:00:00Z", None, 0.05,
    )
    with _mock_psycopg_connect([completed_row]):
        result = poll_completion(
            "postgresql://x", "incident-1", timeout_seconds=2.0
        )
    assert result is not None
    assert result["investigation_id"] == "inv-1"
    assert result["verdict"] == "true_positive"
    assert result["severity"] == "high"
    assert result["mitre_techniques"] == ["T1110"]
    assert result["total_cost_usd"] == 0.05


def test_poll_completion_returns_none_on_timeout() -> None:
    incomplete = ("inv-1", None, None, [], None, None, None, None)
    with _mock_psycopg_connect([incomplete] * 10):
        # Tight timeout so test stays fast.
        result = poll_completion(
            "postgresql://x", "incident-1", timeout_seconds=0.05
        )
    assert result is None


def test_poll_completion_handles_missing_investigation_row() -> None:
    """Investigation row may not exist yet — incident inserted, worker hasn't picked up."""
    pending = (None, None, None, None, None, None, None, None)
    completed = (
        "inv-1", "benign", "info", [],
        70, "2026-04-30T00:00:00Z", None, 0.01,
    )
    with _mock_psycopg_connect([pending, pending, completed]):
        result = poll_completion(
            "postgresql://x", "incident-1", timeout_seconds=5.0
        )
    assert result is not None
    assert result["verdict"] == "benign"


# ---- fetch_attempts


def test_fetch_attempts_shapes_rows() -> None:
    rows = [
        ("triage", 1, "model-a", "model-a", "success", 100, 50, 0.001, 1500),
        ("triage", 2, "model-b", "model-b", "timeout", None, None, None, 30000),
    ]
    cur = MagicMock()
    cur.fetchall.return_value = rows
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with patch("evals.harness.runner.psycopg.connect", return_value=conn):
        out = fetch_attempts("postgresql://x", "inv-1")
    assert len(out) == 2
    assert out[0]["role"] == "triage"
    assert out[0]["status"] == "success"
    assert out[1]["status"] == "timeout"
    assert out[1]["cost_usd"] is None


# ---- _classify_failure


def test_classify_failure_returns_none_on_clean_verdict() -> None:
    assert _classify_failure("true_positive", None, []) is None


def test_classify_failure_fallback_keyword() -> None:
    assert (
        _classify_failure(
            "inconclusive", "fallback chain exhausted", []
        )
        == "fallback_exhausted"
    )


def test_classify_failure_timeout_keyword() -> None:
    assert (
        _classify_failure("inconclusive", "timeout after 30s", [])
        == "timeout"
    )


def test_classify_failure_inferred_from_attempts() -> None:
    attempts = [{"status": "validation_fail"}]
    assert _classify_failure("inconclusive", None, attempts) == "schema"


def test_classify_failure_falls_back_to_ambiguous() -> None:
    assert (
        _classify_failure("inconclusive", "weird thing", [{"status": "success"}])
        == "ambiguous_label"
    )


# ---- run_one


def test_run_one_completed(tmp_path: Path) -> None:
    fixture = tmp_path / "f.json"
    fixture.write_text(json.dumps({"_time": "0", "src_ip": "1.1.1.1"}))

    incident = LabeledIncident(
        id="x",
        fixture=str(fixture.relative_to(tmp_path)),
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110"],
    )

    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"incident_id": "i-1", "status": "accepted"}
    client = MagicMock()
    client.post.return_value = response

    completion = {
        "investigation_id": "inv-1",
        "verdict": "true_positive",
        "severity": "high",
        "mitre_techniques": ["T1110"],
        "confidence": 90,
        "completed_at": "2026-04-30T00:00:00Z",
        "inconclusive_reason": None,
        "total_cost_usd": 0.05,
    }
    attempts = [{"role": "triage", "status": "success"}]

    with (
        patch(
            "evals.harness.runner.poll_completion", return_value=completion
        ),
        patch(
            "evals.harness.runner.fetch_attempts", return_value=attempts
        ),
    ):
        result = run_one(
            incident,
            client=client,
            dsn="postgresql://x",
            secret="s",
            timeout_seconds=10.0,
            repo_root=tmp_path,
        )

    assert result.runner_status == "completed"
    assert result.investigation_id == "inv-1"
    assert result.verdict == "true_positive"
    assert result.cost_usd == 0.05
    assert result.attempts == attempts
    assert result.fail_category is None


def test_run_one_ingest_failed(tmp_path: Path) -> None:
    fixture = tmp_path / "f.json"
    fixture.write_text(json.dumps({"_time": "0"}))

    incident = LabeledIncident(
        id="x",
        fixture=str(fixture.relative_to(tmp_path)),
        expected_verdict="benign",
        expected_severity="info",
        expected_techniques=[],
    )

    response = MagicMock()
    response.status_code = 401
    response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "401", request=MagicMock(), response=response
    )
    client = MagicMock()
    client.post.return_value = response

    result = run_one(
        incident,
        client=client,
        dsn="postgresql://x",
        secret="bad",
        timeout_seconds=10.0,
        repo_root=tmp_path,
    )
    assert result.runner_status == "ingest_failed"
    assert result.investigation_id is None
    assert result.fail_category == "prompt"


def test_run_one_timeout(tmp_path: Path) -> None:
    fixture = tmp_path / "f.json"
    fixture.write_text(json.dumps({"_time": "0"}))

    incident = LabeledIncident(
        id="x",
        fixture=str(fixture.relative_to(tmp_path)),
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110"],
    )

    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"incident_id": "i-1", "status": "accepted"}
    client = MagicMock()
    client.post.return_value = response

    with patch("evals.harness.runner.poll_completion", return_value=None):
        result = run_one(
            incident,
            client=client,
            dsn="postgresql://x",
            secret="s",
            timeout_seconds=0.05,
            repo_root=tmp_path,
        )

    assert result.runner_status == "timeout"
    assert result.fail_category == "timeout"
    assert result.investigation_id is None


# ---- end-to-end sanity (report renderer + scoring + runner mock)


def test_report_renders_clean_html(tmp_path: Path, monkeypatch) -> None:
    """End-to-end mini-eval: fixture → mock-runner → score → report."""
    from evals.harness.report import render_report
    from evals.harness.runner import IncidentResult
    from evals.harness.scoring import score_incident, summarize

    fixture = tmp_path / "f.json"
    fixture.write_text(json.dumps({"_time": "0", "src_ip": "1.1.1.1"}))

    incident = LabeledIncident(
        id="x",
        fixture=str(fixture.relative_to(tmp_path)),
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110", "T1110.001"],
        notes="brute force",
    )
    result = IncidentResult(
        incident_id="x",
        investigation_id="inv-1",
        runner_status="completed",
        verdict="true_positive",
        severity="high",
        mitre_techniques=["T1110"],  # partial match → diff block renders
        confidence=85,
        inconclusive_reason=None,
        cost_usd=0.05,
        latency_ms=8000,
        attempts=[{"role": "triage", "status": "success"}],
        fail_category=None,
    )
    rubric = json.loads(
        (
            Path(__file__).resolve().parents[1] / "rubrics" / "v1.json"
        ).read_text()
    )
    score = score_incident(
        incident_id=incident.id,
        expected_verdict=incident.expected_verdict,
        expected_severity=incident.expected_severity,
        expected_techniques=incident.expected_techniques,
        actual_verdict=result.verdict,
        actual_severity=result.severity,
        actual_techniques=result.mitre_techniques,
        runner_status=result.runner_status,
        fail_category=result.fail_category,
        cost_usd=result.cost_usd,
        latency_ms=result.latency_ms,
        rubric=rubric,
    )
    summary = summarize([score], rubric)

    from datetime import UTC, datetime
    html_out = render_report(
        summary=summary,
        scores=[score],
        incidents=[incident],
        results=[result],
        rubric=rubric,
        dataset_path=tmp_path / "ds.jsonl",
        rubric_version="v1",
        run_started_at=datetime(2026, 4, 30, 12, 0, 0, tzinfo=UTC),
    )
    assert "<!DOCTYPE html>" in html_out
    assert "Sentient eval report" in html_out
    assert "true_positive" in html_out
    assert "T1110" in html_out
    assert "brute force" in html_out
    assert "PASS" in html_out  # perfect score
