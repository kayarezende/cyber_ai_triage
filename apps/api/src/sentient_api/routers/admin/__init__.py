"""Wk-10 admin panel routers.

Five surfaces, one per file. Each lives behind `RequireAdmin` so dev-bypass
analysts get 403; only admins see the panel. Mounted by `main.py` under
`/api/admin/*`.
"""

from __future__ import annotations

from sentient_api.routers.admin import (
    budgets,
    hitl_policies,
    llm_roles,
    splunk_creds,
    users,
)

__all__ = ["budgets", "hitl_policies", "llm_roles", "splunk_creds", "users"]
