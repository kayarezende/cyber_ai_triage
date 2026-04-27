"""Wk-8 seed: 10 global detection rules.

Each row is `tenant_id IS NULL` so it's visible to every tenant per the wk-2
RLS policy on `detection_rules` (`USING (tenant_id IS NULL OR tenant_id = ...)`)
Wk-8 migration adds a partial unique index on `(name) WHERE tenant_id IS NULL`
so this script is idempotent: re-running upserts the rule body without
duplicating rows.

T-codes verified against the `mitre_techniques` table seeded by `seed_mitre.py`
(691 enterprise techniques from MITRE ATT&CK STIX).

Severity override semantics: `effective_severity = max(agent_severity,
rule.severity_override)`. Rule 10 (`valid_accounts_only`) is intentionally a
floor (`low`) — it tags every T1078 observation but won't escalate above what
the agent already drafted.

Run as DB owner / superuser so the RLS WITH CHECK clause permits
`tenant_id IS NULL` inserts (mirror `seed_mitre.py` precedent).

Usage:
    uv run python db/seeds/seed_detection_rules.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg

_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Mirror the seeder pattern from `seed_mitre.py`."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _resolve_dsn() -> str:
    _load_dotenv(_ROOT / ".env")
    dsn = os.environ.get(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sentient",
    )
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


# (name, description, required_techniques, any_techniques, severity_override)
_RULES: list[tuple[str, str, list[str], list[str], str]] = [
    (
        "ransomware_kill_chain",
        "PowerShell execution + data encryption with C2 indicators.",
        ["T1059.001", "T1486"],
        ["T1071", "T1071.001", "T1071.004"],
        "critical",
    ),
    (
        "credential_dumping_then_lateral",
        "Credential dumping (T1003) followed by remote-services lateral movement.",
        ["T1003", "T1021"],
        ["T1021.001", "T1021.002", "T1021.006"],
        "critical",
    ),
    (
        "interactive_privilege_escalation",
        "Valid-accounts use combined with a privilege-escalation exploit.",
        ["T1078", "T1068"],
        [],
        "high",
    ),
    (
        "defense_evasion_clearlogs",
        "Windows event-log clearing alongside command interpreter execution.",
        ["T1070.001"],
        ["T1059.001", "T1059.003"],
        "high",
    ),
    (
        "cloud_iam_persistence",
        "Additional cloud roles assigned (T1098.003) by a cloud account (T1078.004).",
        ["T1098.003"],
        ["T1078.004"],
        "high",
    ),
    (
        "data_exfil_over_c2",
        "Data exfiltration over the same channel as C2 / web service.",
        ["T1041"],
        ["T1071", "T1567", "T1567.002"],
        "critical",
    ),
    (
        "phishing_with_macro",
        "Spearphishing attachment opened, plus user execution and (optionally) macro code.",
        ["T1566.001", "T1204.002"],
        ["T1059.005"],
        "high",
    ),
    (
        "living_off_the_land_proxy_chain",
        "Signed-binary proxy execution (rundll32) plus another LOLBin or PowerShell.",
        ["T1218.011"],
        ["T1059.001", "T1218.005"],
        "medium",
    ),
    (
        "webshell_persistence",
        "Web shell installed (T1505.003), often after exploitation of a public-facing app.",
        ["T1505.003"],
        ["T1190"],
        "high",
    ),
    (
        # Floor only — never escalates. Tags every valid-accounts observation
        # so the analyst panel can surface "single-T MITRE tag" investigations
        # without distorting severity for benign service-account logins.
        "valid_accounts_only",
        "Valid-accounts technique alone (no chain) — severity floor only.",
        ["T1078"],
        [],
        "low",
    ),
]


_UPSERT_SQL = """
    INSERT INTO detection_rules (
        tenant_id, name, description,
        required_techniques, any_techniques,
        severity_override, enabled
    )
    VALUES (NULL, %s, %s, %s, %s, %s, TRUE)
    ON CONFLICT (name) WHERE tenant_id IS NULL DO UPDATE SET
        description         = EXCLUDED.description,
        required_techniques = EXCLUDED.required_techniques,
        any_techniques      = EXCLUDED.any_techniques,
        severity_override   = EXCLUDED.severity_override,
        enabled             = TRUE
"""


def main() -> int:
    dsn = _resolve_dsn()
    rows = [
        (name, desc, required, any_, override)
        for name, desc, required, any_, override in _RULES
    ]
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.executemany(_UPSERT_SQL, rows)
        cur.execute("SELECT COUNT(*) FROM detection_rules WHERE tenant_id IS NULL")
        row = cur.fetchone()
        total = int(row[0]) if row else 0
        conn.commit()
    print(f"seeded {len(rows)} global detection rules (total: {total})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
