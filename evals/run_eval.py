"""CLI entry: drive a labeled dataset through the live ingest path,
score, render an HTML report.

Usage:
    python evals/run_eval.py \\
        --dataset evals/datasets/golden.jsonl \\
        --rubric evals/rubrics/v1.json \\
        --output evals/reports/baseline-2026-04-30.html

Env:
    EVAL_API_BASE        default http://localhost:8000
    DATABASE_URL         default postgresql://postgres:postgres@localhost:5432/sentient
    INGEST_WEBHOOK_SECRET   required

Exit codes:
    0  overall + verdict + MITRE thresholds met
    1  one or more thresholds missed (CI gate)
    2  config / connectivity error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# Allow `python evals/run_eval.py` from the repo root by putting the repo
# on sys.path; the absolute imports below then resolve under both that
# script form and `python -m evals.run_eval`.
if __name__ == "__main__" and __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.harness.report import render_report  # noqa: E402
from evals.harness.runner import REPO_ROOT, load_dataset, run_dataset  # noqa: E402
from evals.harness.scoring import RunSummary, score_incident, summarize  # noqa: E402

DEFAULT_API_BASE = "http://localhost:8000"
DEFAULT_DSN = "postgresql://postgres:postgres@localhost:5432/sentient"
DEFAULT_TIMEOUT_SECONDS = 120.0


def _normalise_dsn(raw: str) -> str:
    """psycopg accepts the bare scheme; SQLAlchemy adds a +psycopg suffix."""
    return raw.replace("postgresql+psycopg://", "postgresql://", 1)


def _check_env(secret: str) -> None:
    if not secret or secret.startswith("CHANGEME"):
        print(
            "ERROR: INGEST_WEBHOOK_SECRET not set (or still placeholder).",
            file=sys.stderr,
        )
        print(
            "Hint: source .env or `export INGEST_WEBHOOK_SECRET=<secret>`",
            file=sys.stderr,
        )
        sys.exit(2)


def _print_summary(summary: RunSummary) -> None:
    """One-line digest for terminal + CI logs."""
    print(
        f"verdict={summary.verdict_accuracy:.2%} "
        f"mitre_f1={summary.mitre_f1_mean:.2f} "
        f"severity={summary.severity_mean:.2f} "
        f"overall={summary.overall_mean:.2f} "
        f"cost=${summary.total_cost_usd:.4f} "
        f"({'PASS' if summary.overall_pass else 'FAIL'})"
    )
    if summary.fail_buckets:
        print(f"failures: {dict(summary.fail_buckets)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPO_ROOT / "evals" / "datasets" / "golden.jsonl",
    )
    parser.add_argument(
        "--rubric",
        type=Path,
        default=REPO_ROOT / "evals" / "rubrics" / "v1.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after N incidents. Default: run the whole dataset.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-incident wait for completed_at. Default 120s.",
    )
    parser.add_argument(
        "--rubric-version",
        type=str,
        default=None,
        help="Override the version label printed in the report header. "
        "Default: read from rubric file.",
    )
    parser.add_argument(
        "--model-override",
        type=str,
        default=None,
        help="Reserved — not implemented in v1. Edit llm_role_config "
        "directly to swap models for now.",
    )
    args = parser.parse_args()

    if args.model_override:
        print(
            "WARN: --model-override is reserved for v1.1; ignored. "
            "Update llm_role_config row to swap models.",
            file=sys.stderr,
        )

    api_base = os.environ.get("EVAL_API_BASE", DEFAULT_API_BASE)
    dsn = _normalise_dsn(os.environ.get("DATABASE_URL", DEFAULT_DSN))
    secret = os.environ.get("INGEST_WEBHOOK_SECRET", "")
    _check_env(secret)

    rubric = json.loads(args.rubric.read_text())
    rubric_version = args.rubric_version or rubric.get("version", args.rubric.stem)

    incidents = load_dataset(args.dataset, limit=args.limit)
    if not incidents:
        print(f"ERROR: no rows in {args.dataset}", file=sys.stderr)
        return 2

    print(
        f"Running {len(incidents)} incident(s) against {api_base} "
        f"(rubric={rubric_version})…"
    )
    started_at = datetime.now(UTC)
    results = run_dataset(
        incidents,
        api_base=api_base,
        dsn=dsn,
        secret=secret,
        timeout_seconds=args.timeout_seconds,
    )

    incidents_by_id = {i.id: i for i in incidents}
    scores = [
        score_incident(
            incident_id=r.incident_id,
            expected_verdict=incidents_by_id[r.incident_id].expected_verdict,
            expected_severity=incidents_by_id[r.incident_id].expected_severity,
            expected_techniques=incidents_by_id[r.incident_id].expected_techniques,
            actual_verdict=r.verdict,
            actual_severity=r.severity,
            actual_techniques=r.mitre_techniques,
            runner_status=r.runner_status,
            fail_category=r.fail_category,
            cost_usd=r.cost_usd,
            latency_ms=r.latency_ms,
            rubric=rubric,
        )
        for r in results
    ]
    summary = summarize(scores, rubric)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        render_report(
            summary=summary,
            scores=scores,
            incidents=incidents,
            results=results,
            rubric=rubric,
            dataset_path=args.dataset,
            rubric_version=rubric_version,
            run_started_at=started_at,
        )
    )
    print(f"Report → {args.output}")
    _print_summary(summary)

    return 0 if summary.overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
