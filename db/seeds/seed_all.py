"""Run every seed in dependency order. Idempotent.

Used by the compose `seed` one-shot service so cold-start
(`docker compose down -v && up -d`) is hands-free. Each seed is its own
script with its own `main()`; we subprocess them rather than import so
the seeds keep working as standalone CLI tools and we don't have to
turn `db/seeds/` into a package.

Order matters:
    1. setup_checkpointer  — LangGraph checkpoint tables (independent)
    2. setup_minio         — evidence bucket (needs MinIO healthy)
    3. seed_tenants        — dev tenant row (FK target for everything else)
    4. seed_mitre          — 691 MITRE techniques (referenced by detection rules)
    5. seed_llm_role_config — per-tenant role config (FK to tenants)
    6. seed_hitl_policies  — default 100% approval policy
    7. seed_detection_rules — 10 global rules (validates against mitre_techniques)

Fail-fast: if any step exits non-zero, abort with the same code so compose
marks the service `service_completed_successfully` only on a clean run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SEEDS_DIR = Path(__file__).resolve().parent

# Ordered list — see module docstring for dependency rationale.
SCRIPTS: tuple[str, ...] = (
    "setup_checkpointer.py",
    "setup_minio.py",
    "seed_tenants.py",
    "seed_mitre.py",
    "seed_llm_role_config.py",
    "seed_hitl_policies.py",
    "seed_detection_rules.py",
)


def main() -> int:
    for script in SCRIPTS:
        path = SEEDS_DIR / script
        print(f"==> {script}", flush=True)
        rc = subprocess.run([sys.executable, str(path)], check=False).returncode
        if rc != 0:
            print(f"!! {script} failed (rc={rc})", file=sys.stderr, flush=True)
            return rc
    print("seeds complete.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
