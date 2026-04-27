"use client";

import { useState, useTransition } from "react";

import { updateUserRole } from "@/lib/server-actions/admin";
import type { TenantUser } from "@/lib/types";

interface Props {
  user: TenantUser;
}

export function UserRow({ user }: Props) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <tr className="border-b border-zinc-900">
      <td className="py-2 font-mono text-xs text-zinc-200">{user.email}</td>
      <td className="py-2">
        <form
          action={(formData: FormData) => {
            setError(null);
            startTransition(async () => {
              const result = await updateUserRole(user.id, formData);
              if (!result.ok) {
                setError(result.detail ?? result.error ?? "save failed");
              }
            });
          }}
          className="flex items-center gap-2"
        >
          <select
            name="role"
            defaultValue={user.role}
            disabled={pending}
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none"
          >
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
          <button
            type="submit"
            disabled={pending}
            className="rounded bg-zinc-700 px-2 py-1 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
          >
            {pending ? "…" : "Save"}
          </button>
          {error ? <span className="text-xs text-red-400">{error}</span> : null}
        </form>
      </td>
      <td className="py-2 font-mono text-xs text-zinc-400">
        {user.entra_oid ? "yes" : "—"}
      </td>
      <td className="py-2 font-mono text-xs text-zinc-400">
        {user.created_at?.slice(0, 10) ?? "—"}
      </td>
    </tr>
  );
}
