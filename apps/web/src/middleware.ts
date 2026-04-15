// Dev-bypass auth middleware (ADR 0011).
//
// When DEV_BYPASS_AUTH=1, pass requests through with an injected x-dev-user
// header so Next.js server components / route handlers can rely on auth
// context. Otherwise, return 501 — Entra SSO lands wk 11 and plugs in here.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const DEV_USER_EMAIL = process.env.DEV_USER_EMAIL ?? "dev@sentientlayer.ai";
const BYPASS_ENABLED = process.env.DEV_BYPASS_AUTH === "1";

export function middleware(request: NextRequest) {
  if (!BYPASS_ENABLED) {
    return NextResponse.json(
      {
        error: "auth_not_implemented",
        detail: "Entra SSO lands wk 11; set DEV_BYPASS_AUTH=1 for local dev.",
      },
      { status: 501 },
    );
  }

  const headers = new Headers(request.headers);
  headers.set("x-dev-user", DEV_USER_EMAIL);

  return NextResponse.next({ request: { headers } });
}

// Matcher excludes Next internals + static assets + the favicon.
export const config = {
  matcher: ["/((?!_next/|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
