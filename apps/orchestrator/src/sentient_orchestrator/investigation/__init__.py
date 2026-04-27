"""Tier-2 LangGraph investigation package (wk-6 skeleton).

Public entry: `run_tier2_investigation`. The main triage runner imports it
after `_finalize_escalated` commits and awaits it in-process.
"""

from sentient_orchestrator.investigation.runner import run_tier2_investigation
from sentient_orchestrator.investigation.state import (
    MAX_TOOL_CALLS,
    InvestigationOutput,
    InvestigationState,
)

__all__ = [
    "MAX_TOOL_CALLS",
    "InvestigationOutput",
    "InvestigationState",
    "run_tier2_investigation",
]
