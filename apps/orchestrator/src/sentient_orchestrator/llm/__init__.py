"""LLMRouter — single LLM call path for the orchestrator.

ADR-0015: app-side fallback loop, direct httpx → OpenRouter, per-attempt
`usage` row for the audit ledger. ADR-0016: reads sovereignty hybrid columns
(BYO key, region constraint, langsmith toggle) from the tenants row.
"""

from __future__ import annotations

from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.llm.router import LLMResult, LLMRouter

__all__ = [
    "FallbackChainExhausted",
    "LLMResult",
    "LLMRouter",
]
