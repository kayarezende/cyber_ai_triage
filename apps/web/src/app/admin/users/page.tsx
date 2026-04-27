import { InviteUserForm } from "@/components/admin/InviteUserForm";
import { UserRow } from "@/components/admin/UserRow";
import { ApiError, apiFetch } from "@/lib/api";
import type { TenantUserListResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  let data: TenantUserListResponse | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<TenantUserListResponse>("/api/admin/users");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        Users
      </h1>
      <p className="text-sm text-zinc-400">
        Inviting creates a row with role + email. Until Entra SSO lands (wk
        11), the user binds to the row at first OIDC login on email match.
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      <table className="w-full border-collapse text-sm">
        <thead className="text-xs uppercase tracking-wide text-zinc-500">
          <tr>
            <th className="border-b border-zinc-800 py-2 text-left">Email</th>
            <th className="border-b border-zinc-800 py-2 text-left">Role</th>
            <th className="border-b border-zinc-800 py-2 text-left">SSO bound</th>
            <th className="border-b border-zinc-800 py-2 text-left">Created</th>
          </tr>
        </thead>
        <tbody>
          {data?.items.map((user) => <UserRow key={user.id} user={user} />)}
        </tbody>
      </table>
      <h2 className="mt-2 text-sm font-semibold tracking-tight text-zinc-200">
        Invite user
      </h2>
      <InviteUserForm />
    </div>
  );
}
