"""LLMRouter exception types."""

from __future__ import annotations

from decimal import Decimal


class FallbackChainExhausted(Exception):  # noqa: N818
    """Raised when every model in [primary, *fallback_chain] failed.

    Carries the role + ordered list of models tried so the runner can populate
    `investigations.inconclusive_reason` for the dashboard.
    """

    def __init__(self, role: str, attempts: list[str]) -> None:
        self.role = role
        self.attempts = attempts
        super().__init__(f"fallback chain exhausted for role={role!r}; " f"attempts={attempts}")


class BudgetExceeded(Exception):  # noqa: N818
    """Raised when a per-investigation cap is already exceeded entering a call.

    `LLMRouter.call()` checks the running totals on `investigations` against
    the per-investigation USD + token caps from `tenants` BEFORE entering the
    fallback loop. If either cap is exceeded, raise here so the runner finalizes
    the investigation as inconclusive with `reason='budget_cap_exceeded'`.

    The check is single-shot per `call()`; one in-flight LLM call may still
    push the post-call total slightly over cap. That is an acceptable single-
    call overshoot bounded by `max_tokens × per-token cost`.
    """

    def __init__(
        self,
        *,
        role: str,
        total_cost_usd: Decimal | float | None,
        cap_usd: Decimal | float | None,
        total_tokens: int | None,
        token_cap: int | None,
    ) -> None:
        self.role = role
        self.total_cost_usd = total_cost_usd
        self.cap_usd = cap_usd
        self.total_tokens = total_tokens
        self.token_cap = token_cap
        # Wk-7 fix #5: keep the message generic. Cap config + running totals
        # are tenant-internal and travel to the audit ledger via structured
        # `emit_budget_exceeded(...)` fields, not via str(exc). Stringified
        # exception text round-trips into log lines + sometimes into UI
        # surfaces (wk-9 analyst panel) — leaking caps there is undesirable.
        super().__init__(f"per-investigation budget exceeded for role={role!r}")


__all__ = ["BudgetExceeded", "FallbackChainExhausted"]
