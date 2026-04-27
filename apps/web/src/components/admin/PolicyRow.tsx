"use client";

import { useState, useTransition } from "react";

import { deleteHitlPolicy } from "@/lib/server-actions/admin";
import type { HitlPolicy } from "@/lib/types";

interface Props {
  policy: HitlPolicy;
}

export function PolicyRow({ policy }: Props) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const editable = policy.tenant_id !== null;

  return (
    <div className="rounded border border-zinc-800 bg-zinc-900 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 text-sm">
            <span className="font-mono text-zinc-100">{policy.name}</span>
            <span className="text-xs text-zinc-500">
              priority {policy.priority}
            </span>
            <span
              className={
                policy.enabled
                  ? "rounded bg-emerald-900 px-1.5 py-0.5 text-xs text-emerald-200"
                  : "rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400"
              }
            >
              {policy.enabled ? "enabled" : "disabled"}
            </span>
            {policy.tenant_id === null ? (
              <span className="rounded bg-amber-900 px-1.5 py-0.5 text-xs text-amber-200">
                global
              </span>
            ) : null}
          </div>
          <pre className="mt-1 max-h-40 overflow-auto rounded bg-zinc-950 p-2 font-mono text-xs text-zinc-300">
            {JSON.stringify(policy.rule_expression, null, 2)}
          </pre>
        </div>
        {editable ? (
          <button
            type="button"
            disabled={pending}
            className="rounded border border-red-800 bg-red-950 px-2 py-1 text-xs text-red-200 hover:bg-red-900 disabled:opacity-60"
            onClick={() => {
              setError(null);
              startTransition(async () => {
                const result = await deleteHitlPolicy(policy.id);
                if (!result.ok) {
                  setError(result.detail ?? result.error ?? "delete failed");
                }
              });
            }}
          >
            {pending ? "Deleting…" : "Delete"}
          </button>
        ) : null}
      </div>
      {error ? (
        <div className="mt-2 text-xs text-red-400">{error}</div>
      ) : null}
    </div>
  );
}
