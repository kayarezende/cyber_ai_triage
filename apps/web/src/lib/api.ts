// Server-only FastAPI fetch wrapper. Server components + server actions use
// this. Talks to the API over the Docker-internal hostname (`http://api:8000`)
// so requests skip Traefik / TLS overhead. Forwards the dev-bypass identity
// headers so DevBypassAuthMiddleware on the API can resolve the tenant.
//
// Wk-11: when Entra lands, replace the header forwarding with the user's
// Bearer token; everything else stays the same.

import "server-only";
import { headers } from "next/headers";

const INTERNAL_BASE = process.env.API_INTERNAL_URL ?? "http://api:8000";

export class ApiError extends Error {
  status: number;
  bodyText: string;
  path: string;

  constructor(status: number, bodyText: string, path: string) {
    super(`API ${status} ${path}: ${bodyText.slice(0, 200)}`);
    this.status = status;
    this.bodyText = bodyText;
    this.path = path;
  }
}

export class NotFoundError extends ApiError {}

interface ApiOptions extends RequestInit {
  searchParams?: Record<string, string | number | boolean | undefined | null>;
}

async function buildHeaders(extra?: HeadersInit): Promise<Headers> {
  const h = await headers();
  const out = new Headers(extra);
  out.set("accept", "application/json");
  if (!out.has("content-type")) {
    out.set("content-type", "application/json");
  }
  const tenant = h.get("x-tenant-id");
  const user = h.get("x-user-id");
  const devUser = h.get("x-dev-user");
  if (tenant) out.set("x-tenant-id", tenant);
  if (user) out.set("x-user-id", user);
  if (devUser) out.set("x-dev-user", devUser);
  return out;
}

function appendSearch(
  url: URL,
  params: ApiOptions["searchParams"],
): void {
  if (!params) return;
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    url.searchParams.set(key, String(value));
  }
}

export async function apiFetch<T>(
  path: string,
  init: ApiOptions = {},
): Promise<T> {
  const url = new URL(path, INTERNAL_BASE);
  appendSearch(url, init.searchParams);
  const built = await buildHeaders(init.headers);
  const res = await fetch(url, {
    ...init,
    headers: built,
    cache: init.cache ?? "no-store",
  });
  const text = await res.text();
  if (!res.ok) {
    if (res.status === 404) throw new NotFoundError(res.status, text, path);
    throw new ApiError(res.status, text, path);
  }
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}
