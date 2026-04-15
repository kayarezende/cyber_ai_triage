"""Dev-bypass auth middleware (ADR 0011).

When DEV_BYPASS_AUTH=1, populate request.state with a synthetic user + tenant
so downstream handlers can rely on auth having run. Else 501 — Entra SSO lands
wk 11 and plugs in here without changing handler code.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from sentient_api.settings import DEV_TENANT_ID, get_settings

# Paths that skip auth entirely (probes, docs, OpenAPI).
_ALLOWLIST: frozenset[str] = frozenset(
    {"/health", "/docs", "/redoc", "/openapi.json"}
)


class DevBypassAuthMiddleware(BaseHTTPMiddleware):
    """Populate request.state.user/tenant_id or reject with 501."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in _ALLOWLIST:
            return await call_next(request)

        settings = get_settings()
        if not settings.dev_bypass_auth:
            return JSONResponse(
                status_code=501,
                content={
                    "error": "auth_not_implemented",
                    "detail": "Entra SSO lands wk 11; set DEV_BYPASS_AUTH=1 for local dev.",
                },
            )

        request.state.user = {
            "email": settings.dev_user_email,
            "role": "admin",
        }
        request.state.tenant_id = DEV_TENANT_ID
        return await call_next(request)
