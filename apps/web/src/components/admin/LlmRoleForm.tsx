"use client";

import { useState, useTransition } from "react";

import { updateLlmRole } from "@/lib/server-actions/admin";
import type { LlmRoleConfig } from "@/lib/types";

interface Props {
  role: LlmRoleConfig;
}

export function LlmRoleForm({ role }: Props) {
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
          const result = await updateLlmRole(role.role, formData);
          if (result.ok) {
            setMessage("Saved.");
          } else {
            setError(result.detail ?? result.error ?? "save failed");
          }
        });
      }}
    >
      <div className="mb-3 flex items-center justify-between">
        <h3 className="font-mono text-sm text-zinc-100">{role.role}</h3>
        <label className="flex items-center gap-2 text-xs text-zinc-400">
          <input
            type="checkbox"
            name="enabled"
            defaultChecked={role.enabled}
            className="h-3 w-3"
          />
          enabled
        </label>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <Field
          label="primary_model"
          name="primary_model"
          defaultValue={role.primary_model}
        />
        <Field
          label="fallback_chain (comma-separated)"
          name="fallback_chain"
          defaultValue={role.fallback_chain.join(", ")}
        />
        <Field
          label="max_tokens"
          name="max_tokens"
          defaultValue={String(role.max_tokens)}
          type="number"
        />
        <Field
          label="temperature"
          name="temperature"
          defaultValue={String(role.temperature)}
          type="number"
          step="0.01"
        />
        <Field
          label="timeout_seconds"
          name="timeout_seconds"
          defaultValue={String(role.timeout_seconds)}
          type="number"
        />
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-zinc-700 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
        >
          {pending ? "Saving…" : "Save"}
        </button>
        {message ? (
          <span className="text-xs text-emerald-400">{message}</span>
        ) : null}
        {error ? <span className="text-xs text-red-400">{error}</span> : null}
      </div>
    </form>
  );
}

interface FieldProps {
  label: string;
  name: string;
  defaultValue: string;
  type?: string;
  step?: string;
}

function Field({ label, name, defaultValue, type = "text", step }: FieldProps) {
  return (
    <label className="flex flex-col gap-1 text-zinc-400">
      {label}
      <input
        name={name}
        type={type}
        step={step}
        defaultValue={defaultValue}
        className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none"
      />
    </label>
  );
}
