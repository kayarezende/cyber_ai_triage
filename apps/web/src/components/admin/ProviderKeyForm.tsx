"use client";

import { useState, useTransition } from "react";

import {
  deleteProviderKey,
  setProviderKey,
} from "@/lib/server-actions/admin";
import type { ProviderKeyStatus } from "@/lib/types";

interface Props {
  status: ProviderKeyStatus;
}

export function ProviderKeyForm({ status }: Props) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <form
      className="rounded border border-zinc-800 bg-zinc-900 p-4"
      action={(formData: FormData) => {
        setMessage(null);
        setError(null);
        startTransition(async () => {
          const result = await setProviderKey(status.provider, formData);
          if (result.ok) {
            setMessage("Saved.");
          } else {
            setError(result.detail ?? result.error ?? "save failed");
          }
        });
      }}
    >
      <div className="mb-3 flex items-center justify-between">
        <h3 className="font-mono text-sm text-zinc-100">{status.provider}</h3>
        <span className="text-xs text-zinc-500">
          {status.is_set ? (
            <span className="text-emerald-400">
              set ••••{status.key_last4 ?? ""}
            </span>
          ) : (
            "not set"
          )}
        </span>
      </div>
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        api_key — leave blank to keep current; entering a value replaces it
        <input
          name="api_key"
          type="password"
          autoComplete="off"
          placeholder={status.is_set ? "•••• stored" : "paste API key"}
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none"
        />
      </label>
      <div className="mt-3 flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-zinc-700 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
        >
          {pending ? "Saving…" : "Save"}
        </button>
        {status.is_set ? (
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              setMessage(null);
              setError(null);
              startTransition(async () => {
                const result = await deleteProviderKey(status.provider);
                if (result.ok) {
                  setMessage("Deleted.");
                } else {
                  setError(result.detail ?? result.error ?? "delete failed");
                }
              });
            }}
            className="rounded border border-red-900 px-3 py-1.5 text-xs text-red-300 hover:bg-red-950 disabled:opacity-60"
          >
            Delete
          </button>
        ) : null}
        {message ? (
          <span className="text-xs text-emerald-400">{message}</span>
        ) : null}
        {error ? <span className="text-xs text-red-400">{error}</span> : null}
      </div>
    </form>
  );
}
