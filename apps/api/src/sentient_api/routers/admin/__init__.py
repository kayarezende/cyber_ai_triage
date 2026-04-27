"""Admin panel routers (wk-10 + wk-11).

Six surfaces, one per file. Each lives behind `RequireAdmin` so dev-bypass
analysts get 403; only admins see the panel. Mounted by `main.py` under
`/api/admin/*`. `usage` is read-only; the rest are CRUD over tenant config.
"""

from __future__ import annotations

from sentient_api.routers.admin import (
    budgets,
    hitl_policies,
    llm_roles,
    splunk_creds,
    usage,
    users,
)

__all__ = [
    "budgets",
    "hitl_policies",
    "llm_roles",
    "splunk_creds",
    "usage",
    "users",
]
