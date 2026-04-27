"""LLMRouter exception types."""

from __future__ import annotations


class FallbackChainExhausted(Exception):  # noqa: N818
    """Raised when every model in [primary, *fallback_chain] failed.

    Carries the role + ordered list of models tried so the runner can populate
    `investigations.inconclusive_reason` for the dashboard.
    """

    def __init__(self, role: str, attempts: list[str]) -> None:
        self.role = role
        self.attempts = attempts
        super().__init__(
            f"fallback chain exhausted for role={role!r}; "
            f"attempts={attempts}"
        )


__all__ = ["FallbackChainExhausted"]
