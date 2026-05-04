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
from decimal import Decimal
from typing import Any
from uuid import UUID

import httpx
from pydantic import BaseModel, ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.crypto import decrypt
from sentient_common.logging import get_logger
from sentient_orchestrator.llm.exceptions import (
    BudgetExceeded,
    FallbackChainExhausted,
)
from sentient_orchestrator.llm.openrouter import (
    OpenRouterResponse,
    OpenRouterToolCall,
    call_chat_completion,
)
from sentient_orchestrator.llm.usage import (
    UsageStatus,
    log_usage_attempt,
    update_investigation_totals,
)

log = get_logger(__name__)

ACTIVE_ROLES = frozenset({"triage", "investigation", "review", "summarize", "entity_extraction"})


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
    #: Per-investigation USD cap. NULL = disabled.
    per_investigation_budget_usd: Decimal | None
    #: Per-investigation token cap (input+output combined). NULL = disabled.
    per_investigation_token_cap: int | None


@dataclass(frozen=True)
class LLMResult:
    """One successful LLM call's normalized output.

    ``cost_usd`` is ``Decimal`` end-to-end inside the orchestrator (cluster C
    / HIGH-8). Float conversion happens only at JSON emission boundaries
    (evidence manifest).
    """

    content: str
    parsed: BaseModel | None
    model_requested: str
    model_used: str
    attempt_num: int
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_usd: Decimal | None
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

        # Wk-7: per-investigation cost + token cap gate. Reads running totals
        # from `investigations` (maintained by the post-attempt accumulator
        # UPDATE inside `_attempt` and `_log_failure`). NULL OR 0 on either
        # cap = disabled (cluster C / MED-1). Cluster C / HIGH-6: re-checked
        # at the top of every fallback iteration so a failure-with-response
        # that pushed us over cap aborts the next iteration before spending
        # more. Cluster C / HIGH-7: SELECT FOR UPDATE serialises concurrent
        # callers on the same investigation_id (lock holds for txn lifetime).
        budget_check_id: UUID | None = None
        if investigation_id is not None:
            cap_usd = self._tenant_cfg.per_investigation_budget_usd
            token_cap = self._tenant_cfg.per_investigation_token_cap
            cap_usd_active = cap_usd is not None and cap_usd > 0
            token_cap_active = token_cap is not None and token_cap > 0
            if cap_usd_active or token_cap_active:
                budget_check_id = investigation_id

        models = [role_cfg.primary_model, *role_cfg.fallback_chain]
        async with httpx.AsyncClient() as client:
            for attempt_num, model in enumerate(models, start=1):
                if budget_check_id is not None:
                    self._check_budget(role=role, investigation_id=budget_check_id)
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

        # HTTP succeeded. Validate body if a schema was supplied. Cluster C
        # / CRIT-5: when the schema-retry HTTP call fires, it writes its own
        # usage row + accumulator UPDATE *inside* _validate_with_retry (so
        # the retry's tokens land in the ledger and the cap gate). The
        # `did_log` flag tells us whether to skip the caller-side log+accum
        # below to avoid double-counting the primary failure row.
        parsed: BaseModel | None = None
        winning_response: OpenRouterResponse = response
        caller_must_log = True
        if response_schema is not None:
            parsed_or_none, retry_response, retry_did_log = await self._validate_with_retry(
                client=client,
                model=model,
                role=role,
                role_cfg=role_cfg,
                messages=messages,
                response_format=response_format,
                response=response,
                response_schema=response_schema,
                attempt_num=attempt_num,
                investigation_id=investigation_id,
            )
            if parsed_or_none is None:
                # _validate_with_retry already logged the primary failure
                # (retry_seq=0) and any retry sub-event (retry_seq=1).
                # Caller does NOT re-log; just advance the fallback chain.
                raise _AttemptFailedError("validation_fail") from None
            parsed = parsed_or_none
            if retry_did_log:
                # Retry path fully self-managed: ledger has primary fail
                # row + retry success row, both accumulated. LLMResult is
                # built from the retry response (it's the call that won).
                caller_must_log = False
                if retry_response is not None:
                    winning_response = retry_response

        if caller_must_log:
            log_usage_attempt(
                self._conn,
                tenant_id=self._tenant_id,
                investigation_id=investigation_id,
                role=role,
                attempt_num=attempt_num,
                model_requested=model,
                model_used=winning_response.model_used or model,
                status="success",
                input_tokens=winning_response.input_tokens,
                output_tokens=winning_response.output_tokens,
                cached_tokens=winning_response.cached_tokens,
                cost_usd=winning_response.cost_usd,
                openrouter_generation_id=winning_response.generation_id,
                latency_ms=winning_response.latency_ms,
                retry_seq=0,
            )
            if investigation_id is not None:
                # Mirror the per-attempt counters onto the investigations row
                # so the budget gate reads O(1) instead of SUM-ing `usage`.
                # Failed attempts with a token-counted response accumulate
                # via `_log_failure(response=...)`. Schema-retry sub-events
                # accumulate inside `_validate_with_retry` (cluster C / CRIT-5).
                update_investigation_totals(
                    self._conn,
                    investigation_id=investigation_id,
                    input_tokens=winning_response.input_tokens,
                    output_tokens=winning_response.output_tokens,
                    cost_usd=winning_response.cost_usd,
                )

        return LLMResult(
            content=winning_response.content,
            parsed=parsed,
            model_requested=model,
            model_used=winning_response.model_used or model,
            attempt_num=attempt_num,
            input_tokens=winning_response.input_tokens,
            output_tokens=winning_response.output_tokens,
            cached_tokens=winning_response.cached_tokens,
            cost_usd=winning_response.cost_usd,
            latency_ms=winning_response.latency_ms,
            tool_calls=tuple(winning_response.tool_calls),
        )

    async def _validate_with_retry(
        self,
        *,
        client: httpx.AsyncClient,
        model: str,
        role: str,
        role_cfg: _RoleConfig,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        response: OpenRouterResponse,
        response_schema: type[BaseModel],
        attempt_num: int,
        investigation_id: UUID | None,
    ) -> tuple[BaseModel | None, OpenRouterResponse | None, bool]:
        """Validate; retry once on failure with corrective message.

        Returns ``(parsed, winning_response, did_log)``:

        * ``(parsed, None, False)`` — primary validated first try; caller logs.
        * ``(parsed, retry_response, True)`` — retry succeeded; this method
          logged the primary failure (``retry_seq=0, validation_fail``) AND
          the retry success (``retry_seq=1, success``), accumulating both.
          Caller must skip its own log+accum to avoid double-counting the
          primary.
        * ``(None, None, True)`` — both calls failed; this method logged
          both rows. Caller raises ``_AttemptFailedError`` without re-logging.

        Auth failures (401/403) on the retry call propagate — same policy as
        the initial attempt. The primary failure row is in place before the
        retry begins, so propagation does not lose the primary's audit row.

        Cluster C / CRIT-5: every HTTP call writes its own usage row + runs
        ``update_investigation_totals``. ADR-0015 §"Retry semantics" defines
        the shared ``attempt_num`` + distinguishing ``retry_seq``.
        """
        try:
            return response_schema.model_validate_json(response.content), None, False
        except ValidationError as exc:
            corrective_summary = _summarize_validation_errors(exc)

        # Primary failed schema. Log it (retry_seq=0) + accumulate now —
        # before the retry HTTP call — so a retry that also fails still
        # leaves both rows in the ledger and both costs in the running total.
        self._log_failure(
            attempt_num=attempt_num,
            model_requested=model,
            role=role,
            investigation_id=investigation_id,
            status="validation_fail",
            response=response,
            retry_seq=0,
        )

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
                # Auth on retry — propagate so the operator sees it. The
                # primary failure row is already written; no retry row
                # (matches the primary attempt's auth-failure policy).
                raise
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status=_classify_http_status(exc.response.status_code),
                response=None,
                retry_seq=1,
            )
            return None, None, True
        except httpx.TimeoutException:
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="timeout",
                response=None,
                retry_seq=1,
            )
            return None, None, True
        except httpx.RequestError:
            # Catches ConnectError/ReadError/etc. — bucket as 5xx (closest
            # enum value) so the retry sub-event still gets a row.
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="5xx",
                response=None,
                retry_seq=1,
            )
            return None, None, True
        except ValueError:
            # Malformed retry response (no choices / bad tool_call args).
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="validation_fail",
                response=None,
                retry_seq=1,
            )
            return None, None, True

        try:
            parsed = response_schema.model_validate_json(retry_response.content)
        except ValidationError:
            # Retry HTTP succeeded but body still failed schema. Tokens were
            # spent — accumulate via _log_failure(response=...).
            self._log_failure(
                attempt_num=attempt_num,
                model_requested=model,
                role=role,
                investigation_id=investigation_id,
                status="validation_fail",
                response=retry_response,
                retry_seq=1,
            )
            return None, None, True

        # Retry succeeded. Log retry row (retry_seq=1, success) +
        # accumulator UPDATE so the cap gate sees the spend.
        log_usage_attempt(
            self._conn,
            tenant_id=self._tenant_id,
            investigation_id=investigation_id,
            role=role,
            attempt_num=attempt_num,
            model_requested=model,
            model_used=retry_response.model_used or model,
            status="success",
            input_tokens=retry_response.input_tokens,
            output_tokens=retry_response.output_tokens,
            cached_tokens=retry_response.cached_tokens,
            cost_usd=retry_response.cost_usd,
            openrouter_generation_id=retry_response.generation_id,
            latency_ms=retry_response.latency_ms,
            retry_seq=1,
        )
        if investigation_id is not None:
            update_investigation_totals(
                self._conn,
                investigation_id=investigation_id,
                input_tokens=retry_response.input_tokens,
                output_tokens=retry_response.output_tokens,
                cost_usd=retry_response.cost_usd,
            )
        return parsed, retry_response, True

    def _check_budget(self, *, role: str, investigation_id: UUID) -> None:
        """Pre-call cap gate. Raise ``BudgetExceeded`` if any cap is exceeded.

        Cluster C / HIGH-7: ``SELECT ... FOR UPDATE OF investigations`` locks
        the row so concurrent callers on the same investigation_id serialize.
        The lock holds for the calling transaction's lifetime — the
        ``tenant_session`` block surrounding ``LLMRouter.call()`` may execute
        many ``call()`` invocations; the lock is acquired on first call and
        released when the outer txn commits. Two callers on the same
        investigation_id will serialize; callers on different investigations
        are unaffected (row-level lock).

        Cluster C / MED-1: ``cap_usd == 0`` and ``token_cap == 0`` are
        treated as "disabled," matching the project convention where 0 means
        no limit. Admins editing ``tenants`` via the UI default to 0 (not
        NULL) when setting "no cap" — the convention has to be enforced at
        the read site, not just the write site.
        """
        cap_usd = self._tenant_cfg.per_investigation_budget_usd
        token_cap = self._tenant_cfg.per_investigation_token_cap
        cap_usd_active = cap_usd is not None and cap_usd > 0
        token_cap_active = token_cap is not None and token_cap > 0
        if not cap_usd_active and not token_cap_active:
            # Both caps disabled. Defensive — caller-side outer gate also
            # short-circuits, so reaching this branch is unusual.
            return

        row = self._conn.execute(
            text("""
                SELECT total_input_tokens, total_output_tokens, total_cost_usd
                  FROM investigations
                 WHERE id = :id
                   FOR UPDATE OF investigations
                """),
            {"id": str(investigation_id)},
        ).first()
        if row is None:
            return
        total_in, total_out, total_cost = row
        total_tokens = int((total_in or 0) + (total_out or 0))

        usd_exceeded = (
            cap_usd is not None
            and cap_usd > 0
            and total_cost is not None
            and Decimal(total_cost) >= cap_usd
        )
        token_exceeded = token_cap is not None and token_cap > 0 and total_tokens >= token_cap
        if usd_exceeded or token_exceeded:
            log.warning(
                "per-investigation budget exceeded",
                role=role,
                investigation_id=str(investigation_id),
                total_cost_usd=str(total_cost),
                cap_usd=str(cap_usd) if cap_usd is not None else None,
                total_tokens=total_tokens,
                token_cap=token_cap,
            )
            raise BudgetExceeded(
                role=role,
                total_cost_usd=total_cost,
                cap_usd=cap_usd,
                total_tokens=total_tokens,
                token_cap=token_cap,
            )

    def _log_failure(
        self,
        *,
        attempt_num: int,
        model_requested: str,
        role: str,
        investigation_id: UUID | None,
        status: UsageStatus,
        response: OpenRouterResponse | None = None,
        retry_seq: int = 0,
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
            retry_seq=retry_seq,
        )
        if investigation_id is not None and response is not None:
            # Wk-7 fix: failed attempts that DID reach OpenRouter and got a
            # token-counted response (HTTP error after generation, schema
            # validation_fail) consumed real tokens. Accumulate them so the
            # cap gate sees true spend. Pure transport failures (timeout,
            # network error) have `response is None` — nothing to add.
            update_investigation_totals(
                self._conn,
                investigation_id=investigation_id,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                cost_usd=response.cost_usd,
            )

    # ----------------------------------------------------------------- loaders

    @staticmethod
    def _load_tenant_config(conn: Connection, tenant_id: UUID) -> _TenantConfig:
        row = conn.execute(
            text("""
                SELECT byo_openrouter_key_encrypted,
                       llm_region_constraint,
                       COALESCE(langsmith_enabled, TRUE) AS langsmith_enabled,
                       per_investigation_budget_usd,
                       per_investigation_token_cap
                FROM tenants
                WHERE id = :tid
                """),
            {"tid": str(tenant_id)},
        ).first()
        if row is None:
            msg = f"tenant {tenant_id} not found"
            raise RuntimeError(msg)

        (
            byo_key_encrypted,
            region_constraint,
            langsmith_enabled,
            budget_usd,
            token_cap,
        ) = row
        api_key = _resolve_api_key(byo_key_encrypted)
        return _TenantConfig(
            api_key=api_key,
            region_constraint=region_constraint,
            langsmith_enabled=bool(langsmith_enabled),
            per_investigation_budget_usd=(Decimal(budget_usd) if budget_usd is not None else None),
            per_investigation_token_cap=(int(token_cap) if token_cap is not None else None),
        )

    @staticmethod
    def _load_role_config(conn: Connection, tenant_id: UUID, role: str) -> _RoleConfig:
        row = conn.execute(
            text("""
                SELECT primary_model, fallback_chain,
                       max_tokens, temperature, timeout_seconds, enabled
                FROM llm_role_config
                WHERE tenant_id = :tid AND role = :role
                """),
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
