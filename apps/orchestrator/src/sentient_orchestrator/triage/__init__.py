"""Tier-1 triage role.

One-shot LLM classification of an incoming OCSF Detection Finding. Output
gates the Tier-2 LangGraph runner (wk-6) — low/info severity auto-closes
benign; medium+ escalates.
"""

from __future__ import annotations

from sentient_orchestrator.triage.role import run_triage
from sentient_orchestrator.triage.schemas import TriageOutput

__all__ = ["TriageOutput", "run_triage"]
