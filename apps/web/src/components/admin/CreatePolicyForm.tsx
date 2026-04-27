"use client";

import { useState, useTransition } from "react";

import { createHitlPolicy } from "@/lib/server-actions/admin";

const DEFAULT_RULE = JSON.stringify({ op: "always_true" }, null, 2);

export function CreatePolicyForm() {
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
          const result = await createHitlPolicy(formData);
          if (result.ok) {
            setMessage("Created.");
            (document.getElementById("hitl-form") as HTMLFormElement | null)?.reset();
          } else {
            setError(result.detail ?? result.error ?? "create failed");
          }
        });
      }}
      id="hitl-form"
    >
      <div className="grid grid-cols-2 gap-3">
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          name
          <input
            name="name"
            required
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-400">
          priority
          <input
            name="priority"
            type="number"
            defaultValue={100}
            min={1}
            max={10_000}
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
          />
        </label>
      </div>
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        rule_expression (JSON)
        <textarea
          name="rule_expression"
          rows={6}
          defaultValue={DEFAULT_RULE}
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none"
        />
      </label>
      <label className="flex items-center gap-2 text-xs text-zinc-400">
        <input
          type="checkbox"
          name="enabled"
          defaultChecked
          className="h-3 w-3"
        />
        enabled
      </label>
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-zinc-700 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
        >
          {pending ? "Creating…" : "Create"}
        </button>
        {message ? (
          <span className="text-xs text-emerald-400">{message}</span>
        ) : null}
        {error ? <span className="text-xs text-red-400">{error}</span> : null}
      </div>
    </form>
  );
}
