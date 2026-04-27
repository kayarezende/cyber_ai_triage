import { NextResponse } from "next/server";

// Static healthcheck used by the Docker `HEALTHCHECK` and Traefik probes.
// Cannot fail; allowlisted in middleware so it works even when
// DEV_BYPASS_AUTH is unset (e.g. early in container startup).
export const dynamic = "force-static";

export function GET() {
  return NextResponse.json({ status: "ok", service: "web" });
}
