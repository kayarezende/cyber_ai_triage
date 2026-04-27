"""HTML report renderer for eval runs.

Stdlib only — no Jinja2. Inline CSS, monospace tables, no JS. Designed to
diff cleanly when committed to git (one block per incident, no
randomized ordering, no timestamps in the body besides the run header).
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .runner import IncidentResult, LabeledIncident
from .scoring import IncidentScore, RunSummary

_CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  margin: 24px; color: #1a1a1a; max-width: 1200px;
}
h1 { font-size: 22px; margin-bottom: 4px; }
h2 { font-size: 17px; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
.meta { color: #666; font-size: 12px; margin-bottom: 24px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 6px 10px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
th { background: #f5f5f5; font-weight: 600; }
.pass { color: #047857; font-weight: 600; }
.fail { color: #b91c1c; font-weight: 600; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.badge-pass { background: #d1fae5; color: #065f46; }
.badge-fail { background: #fee2e2; color: #991b1b; }
.badge-warn { background: #fef3c7; color: #92400e; }
.metric { font-size: 28px; font-weight: 600; }
.metric-label { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
.metric-card {
  display: inline-block; padding: 12px 20px; margin-right: 12px;
  border: 1px solid #ddd; border-radius: 6px; min-width: 130px;
}
details { margin: 4px 0; }
details summary { cursor: pointer; color: #2563eb; }
pre { background: #f9fafb; padding: 8px; border-radius: 4px; font-size: 11px; overflow-x: auto; }
code { font-family: "SF Mono", Menlo, monospace; font-size: 12px; }
.mono { font-family: "SF Mono", Menlo, monospace; font-size: 12px; }
"""


def _badge(passed: bool) -> str:
    cls = "badge-pass" if passed else "badge-fail"
    text = "PASS" if passed else "FAIL"
    return f'<span class="badge {cls}">{text}</span>'


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _fmt_cost(value: float | None) -> str:
    if value is None:
        return "—"
    return f"${value:.4f}"


def _row_class(score: IncidentScore) -> str:
    return "pass" if score.verdict_correct else "fail"


def render_report(
    *,
    summary: RunSummary,
    scores: list[IncidentScore],
    incidents: list[LabeledIncident],
    results: list[IncidentResult],
    rubric: dict[str, Any],
    dataset_path: Path,
    rubric_version: str,
    run_started_at: datetime,
) -> str:
    incidents_by_id = {i.id: i for i in incidents}
    results_by_id = {r.incident_id: r for r in results}

    metric_cards = [
        ("Verdict accuracy", _fmt_pct(summary.verdict_accuracy), summary.verdict_pass),
        ("MITRE F1 (mean)", f"{summary.mitre_f1_mean:.2f}", summary.mitre_pass),
        ("Severity (mean)", f"{summary.severity_mean:.2f}", None),
        ("Overall (mean)", f"{summary.overall_mean:.2f}", summary.overall_pass),
    ]

    cards_html = "".join(
        f'<div class="metric-card">'
        f'<div class="metric-label">{html.escape(label)}</div>'
        f'<div class="metric">{html.escape(value)}</div>'
        + (f'<div>{_badge(passed)}</div>' if passed is not None else "")
        + "</div>"
        for label, value, passed in metric_cards
    )

    fail_buckets_html = (
        "".join(
            f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>"
            for k, v in sorted(summary.fail_buckets.items())
        )
        or "<tr><td colspan='2'>No failures categorized.</td></tr>"
    )

    rows_html = "".join(_render_score_row(s, incidents_by_id, results_by_id) for s in scores)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentient eval — {html.escape(rubric_version)} — {run_started_at:%Y-%m-%d}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>Sentient eval report</h1>
<div class="meta">
  Rubric: <code>{html.escape(rubric_version)}</code> ·
  Dataset: <code>{html.escape(str(dataset_path))}</code> ·
  Run started: {run_started_at:%Y-%m-%d %H:%M:%S} ·
  Incidents: {summary.total} ·
  Total cost: {_fmt_cost(summary.total_cost_usd)}
</div>

<div>{cards_html}</div>

<h2>Failure buckets</h2>
<table>
  <thead><tr><th>Category</th><th>Count</th></tr></thead>
  <tbody>{fail_buckets_html}</tbody>
</table>

<h2>Per-incident</h2>
<table>
  <thead>
    <tr>
      <th>ID</th><th>Verdict (actual / expected)</th><th>Severity</th>
      <th>MITRE F1</th><th>Overall</th><th>Cost</th><th>Latency</th><th>Fail</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>

<h2>Rubric</h2>
<pre>{html.escape(json.dumps(rubric, indent=2))}</pre>

</body>
</html>
"""


def _render_score_row(
    score: IncidentScore,
    incidents_by_id: dict[str, LabeledIncident],
    results_by_id: dict[str, IncidentResult],
) -> str:
    inc = incidents_by_id.get(score.incident_id)
    res = results_by_id.get(score.incident_id)

    actual_v = score.verdict_actual or "—"
    expected_v = score.verdict_expected
    cls = _row_class(score)
    verdict_cell = (
        f'<span class="{cls}">{html.escape(actual_v)}</span>'
        f' <span class="mono">/ {html.escape(expected_v)}</span>'
    )
    sev_cell = (
        f"{html.escape(score.severity_actual or '—')} / "
        f"{html.escape(score.severity_expected)} "
        f"<span class='mono'>({score.severity_score:.1f})</span>"
    )
    mitre_cell = (
        f"{score.mitre.f1:.2f} "
        f"<span class='mono'>(p={score.mitre.precision:.2f} r={score.mitre.recall:.2f})</span>"
    )
    fail_cell = html.escape(score.fail_category or "")

    notes_html = ""
    if inc and inc.notes:
        notes_html += (
            f"<details><summary>label notes</summary>"
            f"<pre>{html.escape(inc.notes)}</pre></details>"
        )
    if res and res.attempts:
        attempts_json = json.dumps(res.attempts, indent=2, default=str)
        notes_html += (
            f"<details><summary>attempts ({len(res.attempts)})</summary>"
            f"<pre>{html.escape(attempts_json)}</pre></details>"
        )
    if res and res.inconclusive_reason:
        notes_html += (
            f"<details><summary>inconclusive_reason</summary>"
            f"<pre>{html.escape(res.inconclusive_reason)}</pre></details>"
        )
    if score.mitre.missed or score.mitre.extra:
        diff = {
            "matched": list(score.mitre.matched),
            "missed": list(score.mitre.missed),
            "extra": list(score.mitre.extra),
        }
        notes_html += (
            f"<details><summary>mitre diff</summary>"
            f"<pre>{html.escape(json.dumps(diff, indent=2))}</pre></details>"
        )

    return f"""<tr>
  <td><code>{html.escape(score.incident_id)}</code>{notes_html}</td>
  <td>{verdict_cell}</td>
  <td>{sev_cell}</td>
  <td>{mitre_cell}</td>
  <td>{score.overall:.2f}</td>
  <td>{_fmt_cost(score.cost_usd)}</td>
  <td>{score.latency_ms or '—'} ms</td>
  <td>{fail_cell}</td>
</tr>"""


__all__ = ["render_report"]
