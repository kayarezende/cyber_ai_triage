// Wk-9 dev-bypass middleware (ADR 0011 → Entra wk-11).
//
// Browser app — when DEV_BYPASS_AUTH=1 inject identity headers and pass
// through. Otherwise redirect to /login (browsers handle redirects;
// returning 501 JSON would surface as a raw error blob).
//
// Allowlisted paths (`/login`, `/api/health`, static assets) skip the
// bypass check so the docker healthcheck + login placeholder stay
// reachable when DEV_BYPASS_AUTH is unset.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const DEV_USER_EMAIL = process.env.DEV_USER_EMAIL ?? "dev@sentientlayer.ai";
const DEV_USER_ID =
  process.env.DEV_USER_ID ?? "00000000-0000-0000-0000-0000000000aa";
// Mirrors apps/api/src/sentient_api/settings.py DEV_TENANT_ID. Wk-11
// Entra middleware will overwrite from JWT `tid` claim.
const DEV_TENANT_ID =
  process.env.DEV_TENANT_ID ?? "00000000-0000-0000-0000-000000000001";
const BYPASS_ENABLED = process.env.DEV_BYPASS_AUTH === "1";

const PUBLIC_PATHS = new Set(["/login", "/api/health"]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (PUBLIC_PATHS.has(pathname)) {
    return NextResponse.next();
  }

  if (!BYPASS_ENABLED) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  const headers = new Headers(request.headers);
  headers.set("x-dev-user", DEV_USER_EMAIL);
  headers.set("x-user-id", DEV_USER_ID);
  // Existing API contract: tenant id flows on the X-Tenant-Id header
  // (DevBypassAuthMiddleware reads it under DEV_BYPASS_AUTH=1).
  if (!headers.get("x-tenant-id")) {
    headers.set("x-tenant-id", DEV_TENANT_ID);
  }

  return NextResponse.next({ request: { headers } });
}

// Matcher excludes Next internals + static assets + the favicon.
export const config = {
  matcher: ["/((?!_next/|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
