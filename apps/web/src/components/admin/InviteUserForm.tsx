"use client";

import { useState, useTransition } from "react";

import { inviteUser } from "@/lib/server-actions/admin";

export function InviteUserForm() {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <form
      className="flex flex-col gap-3 rounded border border-zinc-800 bg-zinc-900 p-4"
      action={(formData: FormData) => {
        setMessage(null);
        setError(null);
        startTransition(async () => {
          const result = await inviteUser(formData);
          if (result.ok) {
            setMessage(`Invited ${result.data?.email ?? ""}.`);
          } else {
            setError(result.detail ?? result.error ?? "invite failed");
          }
        });
      }}
    >
      <div className="grid grid-cols-[1fr_120px_auto] gap-3">
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          email
          <input
            name="email"
            type="email"
            required
            placeholder="analyst@founder.local"
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          role
          <select
            name="role"
            defaultValue="analyst"
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
          >
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <div className="flex items-end">
          <button
            type="submit"
            disabled={pending}
            className="rounded bg-zinc-700 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
          >
            {pending ? "Inviting…" : "Invite"}
          </button>
        </div>
      </div>
      {message ? <span className="text-xs text-emerald-400">{message}</span> : null}
      {error ? <span className="text-xs text-red-400">{error}</span> : null}
    </form>
  );
}
