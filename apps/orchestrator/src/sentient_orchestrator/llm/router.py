"""LLMRouter — app-side fallback loop, direct httpx → OpenRouter.

ADR-0015: replaces OpenRouter native `models[]` array fallback with explicit
single-model calls + per-attempt `usage` row. ADR-0016: reads sovereignty
hybrid columns from the tenants row at construction (BYO key, region
constraint, langsmith toggle). MVP keeps these dormant — values flow through
unchanged when NULL/TRUE.

Lifecycle: one router per investigation. `__init__` reads tenant + role-config
state inside the caller's `tenant_session(tenant_id)` connection. Subsequent
`await router.call(role=...)` calls reuse the same connection for the per-attempt
`usage` INSERT so the audit ledger lands in the same transaction as the
investigation row.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
from pydantic import BaseModel, ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.crypto import decrypt
from sentient_common.logging import get_logger
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.llm.openrouter import (
    OpenRouterResponse,
    OpenRouterToolCall,
    call_chat_completion,
)
from sentient_orchestrator.llm.usage import UsageStatus, log_usage_attempt

log = get_logger(__name__)

ACTIVE_ROLES = frozenset(
    {"triage", "investigation", "review", "summarize", "entity_extraction"}
)


@dataclass(frozen=True)
class _RoleConfig:
    primary_model: str
    fallback_chain: list[str]
    max_tokens: int
    temperature: float
    timeout_seconds: int
    enabled: bool


@dataclass(frozen=True)
class _TenantConfig:
    api_key: str
    region_constraint: str | None
    langsmith_enabled: bool


@dataclass(frozen=True)
class LLMResult:
    """One successful LLM call's normalized output."""

    content: str
    parsed: BaseModel | None
    model_requested: str
    model_used: str
    attempt_num: int
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_usd: float | None
    latency_ms: int
    tool_calls: tuple[OpenRouterToolCall, ...] = ()


class LLMRouter:
    """Per-investigation LLMRouter.

    Construct once with the active tenant_session connection; reuse across
    multiple `call()` invocations for the same investigation.
    """

    def __init__(self, tenant_id: UUID, conn: Connection) -> None:
        self._tenant_id = tenant_id
        self._conn = conn
        self._tenant_cfg = self._load_tenant_config(conn, tenant_id)
        self._traced_call = _build_traced_call(self._tenant_cfg.langsmith_enabled)

    # ------------------------------------------------------------------ public

    async def call(
        self,
        *,
        role: str,
        messages: list[dict[str, Any]],
        response_schema: type[BaseModel] | None = None,
        investigation_id: UUID | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResult:
        """Run the fallback loop for one role; return the first successful result.

        `tools` + `tool_choice` are OpenAI-format pass-through (see
        `openrouter.call_chat_completion` for the wire shape). When `tools` is
        supplied, the LLMResult's `tool_calls` field reflects the model's
        chosen calls.

        Mutually exclusive: do not combine `tools` with `response_schema` —
        most providers reject `tools + response_format=json_schema` together,
        and the schema-retry logic doesn't apply when the model is expected
        to emit a tool_call rather than schema-conforming JSON content.
        """
        if role not in ACTIVE_ROLES:
            msg = f"unknown LLM role {role!r}"
            raise ValueError(msg)
        if tools and response_schema is not None:
            msg = "tools and response_schema are mutually exclusive"
            raise ValueError(msg)

        role_cfg = self._load_role_config(self._conn, self._tenant_id, role)
        if not role_cfg.enabled:
            msg = f"LLM role {role!r} is disabled for tenant {self._tenant_id}"
            raise RuntimeError(msg)

        models = [role_cfg.primary_model, *role_cfg.fallback_chain]
        async with httpx.AsyncClient() as client:
            for attempt_num, model in enumerate(models, start=1):
                try:
                    return await self._attempt(
                        client=client,
                        attempt_num=attempt_num,
                        model=model,
                        role=role,
                        role_cfg=role_cfg,
                        messages=messages,
                        response_schema=response_schema,
                        investigation_id=investigation_id,
                        tools=tools,
                        tool_choice=tool_choice,
                    )
                except _AttemptFailedError as exc:
                    log.warning(
                        "llm attempt failed",
                        role=role,
                        attempt_num=attempt_num,
                        model=model,
                        status=exc.status,
                    )
                    # continue to next model

        raise FallbackChainExhausted(role=role, attempts=models)

    # --------------------------------------------------------------- internals

    async def _attempt(
        self,
        *,
        client: httpx.AsyncClient,
        attempt_num: int,
        model: str,
        role: str,
        role_cfg: _RoleConfig,
        messages: list[dict[str, Any]],
        response_schema: type[BaseModel] | None,
        investigation_id: UUID | None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResult:
        """Run one attempt. Raises `_AttemptFailedError` on retryable failure."""
        response_format = _schema_to_response_format(response_schema)

        try:
            response = await self._traced_call(
                client=client,
                api_key=self._tenant_cfg.api_key,
                model=model,
                messages=messages,
                max_tokens=role_cfg.max_tokens,
                temperature=role_cfg.temperature,
                timeout=float(role_cfg.timeout_seconds),
                response_format=response_format,
                region_constraint=self._tenant_cfg.region_constraint,
                tools=tools,
                tool_choice=tool_choice,
            )
        except ValueError:
            # `_parse_response` raises ValueError for malformed model output
            # (no choices, malformed tool_call arguments). Bucket as
            # validation_fail so the next model in the chain gets a turn.
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="validation_fail",
            )
            raise _AttemptFailedError("validation_fail") from None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                # Auth — infra error, not a per-attempt LLM ledger event.
                # Don't retry, don't write a misleading 'validation_fail'
                # row; surface the real error so the operator rotates keys.
                log.error(
                    "openrouter auth failure",
                    role=role,
                    model=model,
                    status_code=exc.response.status_code,
                )
                raise
            status = _classify_http_status(exc.response.status_code)
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status=status,
            )
            raise _AttemptFailedError(status) from None
        except httpx.TimeoutException:
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="timeout",
            )
            raise _AttemptFailedError("timeout") from None
        except httpx.RequestError:
            # Catches ConnectError, ReadError, WriteError, ProxyError,
            # RemoteProtocolError, etc. — any network-level failure that
            # didn't reach an HTTP status. Bucket as '5xx' (closest enum
            # value); the audit chain still gets a row.
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="5xx",
            )
            raise _AttemptFailedError("5xx") from None

        # HTTP succeeded. Validate body if a schema was supplied.
        parsed: BaseModel | None = None
        if response_schema is not None:
            parsed_or_none = await self._validate_with_retry(
                client=client,
                model=model,
                role_cfg=role_cfg,
                messages=messages,
                response_format=response_format,
                response=response,
                response_schema=response_schema,
            )
            if parsed_or_none is None:
                self._log_failure(
                    attempt_num=attempt_num,
                    model_requested=model,
                    role=role,
                    investigation_id=investigation_id,
                    status="validation_fail",
                    response=response,
                )
                raise _AttemptFailedError("validation_fail") from None
            parsed = parsed_or_none

        log_usage_attempt(
            self._conn,
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            role=role,
            attempt_num=attempt_num,
            model_requested=model,
            model_used=response.model_used or model,
            status="success",
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cached_tokens=response.cached_tokens,
            cost_usd=response.cost_usd,
            openrouter_generation_id=response.generation_id,
            latency_ms=response.latency_ms,
        )

        return LLMResult(
            content=response.content,
            parsed=parsed,
            model_requested=model,
            model_used=response.model_used or model,
            attempt_num=attempt_num,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cached_tokens=response.cached_tokens,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
            tool_calls=tuple(response.tool_calls),
        )

    async def _validate_with_retry(
        self,
        *,
        client: httpx.AsyncClient,
        model: str,
        role_cfg: _RoleConfig,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        response: OpenRouterResponse,
        response_schema: type[BaseModel],
    ) -> BaseModel | None:
        """Validate; retry once on failure with corrective message. Returns None on bail.

        Auth failures (401/403) on the retry call propagate — same policy as
        the initial attempt. Other HTTP / network errors collapse to None so
        the outer loop classifies the attempt as `validation_fail` and tries
        the next model.
        """
        try:
            return response_schema.model_validate_json(response.content)
        except ValidationError as exc:
            corrective_summary = _summarize_validation_errors(exc)

        retry_messages: list[dict[str, Any]] = [
            *messages,
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": (
                    "Your previous response failed JSON schema validation. "
                    f"Errors: {corrective_summary}\n"
                    "Return ONLY valid JSON conforming to the schema. "
                    "No prose, no markdown."
                ),
            },
        ]
        try:
            retry_response = await self._traced_call(
                client=client,
                api_key=self._tenant_cfg.api_key,
                model=model,
                messages=retry_messages,
                max_tokens=role_cfg.max_tokens,
                temperature=role_cfg.temperature,
                timeout=float(role_cfg.timeout_seconds),
                response_format=response_format,
                region_constraint=self._tenant_cfg.region_constraint,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                # Auth on retry — propagate so the operator sees it.
                raise
            return None
        except (httpx.TimeoutException, httpx.RequestError):
            return None

        try:
            return response_schema.model_validate_json(retry_response.content)
        except ValidationError:
            return None

    def _log_failure(
        self,
        *,
        attempt_num: int,
        model_requested: str,
        role: str,
        investigation_id: UUID | None,
        status: UsageStatus,
        response: OpenRouterResponse | None = None,
    ) -> None:
        log_usage_attempt(
            self._conn,
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            role=role,
            attempt_num=attempt_num,
            model_requested=model_requested,
            model_used=response.model_used if response else None,
            status=status,
            input_tokens=response.input_tokens if response else None,
            output_tokens=response.output_tokens if response else None,
            cached_tokens=response.cached_tokens if response else None,
            cost_usd=response.cost_usd if response else None,
            openrouter_generation_id=response.generation_id if response else None,
            latency_ms=response.latency_ms if response else None,
        )

    # ----------------------------------------------------------------- loaders

    @staticmethod
    def _load_tenant_config(conn: Connection, tenant_id: UUID) -> _TenantConfig:
        row = conn.execute(
            text(
                """
                SELECT byo_openrouter_key_encrypted,
                       llm_region_constraint,
                       COALESCE(langsmith_enabled, TRUE) AS langsmith_enabled
                FROM tenants
                WHERE id = :tid
                """
            ),
            {"tid": str(tenant_id)},
        ).first()
        if row is None:
            msg = f"tenant {tenant_id} not found"
            raise RuntimeError(msg)

        byo_key_encrypted, region_constraint, langsmith_enabled = row
        api_key = _resolve_api_key(byo_key_encrypted)
        return _TenantConfig(
            api_key=api_key,
            region_constraint=region_constraint,
            langsmith_enabled=bool(langsmith_enabled),
        )

    @staticmethod
    def _load_role_config(
        conn: Connection, tenant_id: UUID, role: str
    ) -> _RoleConfig:
        row = conn.execute(
            text(
                """
                SELECT primary_model, fallback_chain,
                       max_tokens, temperature, timeout_seconds, enabled
                FROM llm_role_config
                WHERE tenant_id = :tid AND role = :role
                """
            ),
            {"tid": str(tenant_id), "role": role},
        ).first()
        if row is None:
            msg = f"no llm_role_config row for tenant={tenant_id} role={role!r}"
            raise RuntimeError(msg)
        return _RoleConfig(
            primary_model=row[0],
            fallback_chain=list(row[1] or []),
            max_tokens=int(row[2]),
            temperature=float(row[3]),
            timeout_seconds=int(row[4]),
            enabled=bool(row[5]),
        )


# ----------------------------------------------------------------- helpers


class _AttemptFailedError(Exception):
    """Internal — signals retryable failure, carries the usage status."""

    def __init__(self, status: UsageStatus) -> None:
        self.status = status
        super().__init__(status)


def _classify_http_status(code: int) -> UsageStatus:
    if code >= 500:
        return "5xx"
    if code == 429:
        return "rate_limited"
    return "validation_fail"


def _schema_to_response_format(
    schema: type[BaseModel] | None,
) -> dict[str, Any] | None:
    """Build OpenAI-compatible json_schema response_format from a Pydantic model."""
    if schema is None:
        return None
    return {
        "type": "json_schema",
        "json_schema": {
            "name": schema.__name__,
            "strict": True,
            "schema": schema.model_json_schema(),
        },
    }


def _build_traced_call(
    langsmith_enabled: bool,
) -> Callable[..., Awaitable[OpenRouterResponse]]:
    """Wrap `call_chat_completion` with `langsmith.traceable` when permitted.

    Per ADR-0016: a tenant with `langsmith_enabled=False` (sovereign-mode)
    must NOT ship trace payloads to LangSmith. We gate at construction so
    the cost is paid once per investigation, not per call.

    When the wrapper is applied, traces ship only if process-level
    `LANGCHAIN_TRACING_V2=true` is also set (handled by `init_tracing()`).
    """
    if not langsmith_enabled:
        return call_chat_completion
    try:
        from langsmith import traceable
    except ImportError:  # pragma: no cover — langsmith is an orchestrator dep
        return call_chat_completion
    return traceable(name="openrouter_chat_completion")(call_chat_completion)


def _summarize_validation_errors(exc: ValidationError) -> str:
    """Render a Pydantic ValidationError without leaking attacker-controlled input.

    `str(exc)` includes `input_value=…` echoes which create a prompt-injection
    surface when the original prompt was built from Splunk fields. We return
    only `(loc, type, msg)` tuples — enough for the model to fix its output.
    """
    parts: list[str] = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(x) for x in err.get("loc", ()))
        parts.append(f"{loc}: {err.get('type', '')} — {err.get('msg', '')}")
    return "; ".join(parts) or "schema validation failed"


def _resolve_api_key(byo_encrypted: bytes | None) -> str:
    """Return BYO-decrypted key if set, else OPENROUTER_API_KEY env var."""
    if byo_encrypted:
        return decrypt(bytes(byo_encrypted))
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key or key.startswith("CHANGEME_"):
        msg = "OPENROUTER_API_KEY not configured"
        raise RuntimeError(msg)
    return key


__all__ = ["ACTIVE_ROLES", "LLMResult", "LLMRouter"]
