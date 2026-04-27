"""Dev-bypass auth middleware (ADR 0011).

When DEV_BYPASS_AUTH=1, populate request.state with a synthetic user + tenant
so downstream handlers can rely on auth having run. Else 501 — Entra SSO lands
wk 11 and plugs in here without changing handler code.

Wk-9: under dev-bypass the middleware honours an `X-Tenant-Id` request header
so the wk-9 web UI (and any future MSSP-style routing) can target a specific
tenant without code changes. The header is only trusted under bypass; in
prod (wk-11) Entra writes `request.state.tenant_id` from the JWT `tid` claim
and ignores the header entirely.

Wk-10: same dev-bypass-only treatment for `X-Dev-Role` so the wk-10 admin
panel routers can be exercised as both `analyst` (403 expected) and `admin`
(200) without monkeypatching middleware in every test. Defaults to `admin`
to keep existing dev sessions unchanged. Post Entra (wk 11) the role comes
from the JWT `roles` claim and the header is ignored.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import UUID

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from sentient_api.settings import DEV_TENANT_ID, get_settings

# Paths that skip auth entirely (probes, docs, OpenAPI, machine-to-machine
# webhooks). The ingest webhook authenticates via a shared secret in the body
# (ADR-0021), not via Entra/dev-bypass user auth.
_ALLOWLIST: frozenset[str] = frozenset(
    {
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/incidents/ingest",
    }
)


_VALID_DEV_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


def _resolve_tenant_id(request: Request, default: str) -> str:
    """Read X-Tenant-Id (dev-bypass only); fall back to DEV_TENANT_ID.

    Returns a UUID-shaped string. Invalid header → 400 surfaced via raising;
    the middleware catches and converts.
    """
    header = request.headers.get("X-Tenant-Id")
    if not header:
        return default
    try:
        return str(UUID(header))
    except ValueError as exc:
        msg = "X-Tenant-Id is not a valid UUID"
        raise ValueError(msg) from exc


def _resolve_role(request: Request, default: str = "admin") -> str:
    """Read X-Dev-Role (dev-bypass only); fall back to admin.

    Restricted to the values `users.role` accepts. Unknown values raise
    so the middleware returns a 400 — mirrors X-Tenant-Id ergonomics.
    """
    header = request.headers.get("X-Dev-Role")
    if not header:
        return default
    if header not in _VALID_DEV_ROLES:
        msg = f"X-Dev-Role must be one of {sorted(_VALID_DEV_ROLES)}"
        raise ValueError(msg)
    return header


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

        try:
            tenant_id = _resolve_tenant_id(request, DEV_TENANT_ID)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_tenant_header", "detail": str(exc)},
            )
        try:
            role = _resolve_role(request)
        except ValueError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_role_header", "detail": str(exc)},
            )

        request.state.user = {
            "email": settings.dev_user_email,
            "role": role,
        }
        request.state.tenant_id = tenant_id
        return await call_next(request)
