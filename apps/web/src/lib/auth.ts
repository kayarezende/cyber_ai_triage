import "server-only";
import { headers } from "next/headers";

export interface CurrentUser {
  email: string;
  userId: string;
  tenantId: string;
}

export async function currentUser(): Promise<CurrentUser> {
  const h = await headers();
  return {
    email: h.get("x-dev-user") ?? "unknown",
    userId: h.get("x-user-id") ?? "unknown",
    tenantId: h.get("x-tenant-id") ?? "unknown",
  };
}
