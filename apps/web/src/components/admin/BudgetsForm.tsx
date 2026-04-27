"use client";

import { useState, useTransition } from "react";

import { updateBudgets } from "@/lib/server-actions/admin";
import type { TenantBudgets } from "@/lib/types";

interface Props {
  budgets: TenantBudgets;
}

export function BudgetsForm({ budgets }: Props) {
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
          const result = await updateBudgets(formData);
          if (result.ok) {
            setMessage("Saved.");
          } else {
            setError(result.detail ?? result.error ?? "save failed");
          }
        });
      }}
    >
      <div className="grid grid-cols-2 gap-4">
        <Field
          label="max_concurrent_investigations"
          name="max_concurrent_investigations"
          defaultValue={budgets.max_concurrent_investigations}
        />
        <Field
          label="monthly_llm_budget_usd"
          name="monthly_llm_budget_usd"
          defaultValue={budgets.monthly_llm_budget_usd}
          step="0.01"
        />
        <Field
          label="per_investigation_budget_usd"
          name="per_investigation_budget_usd"
          defaultValue={budgets.per_investigation_budget_usd}
          step="0.01"
        />
        <Field
          label="per_investigation_token_cap"
          name="per_investigation_token_cap"
          defaultValue={budgets.per_investigation_token_cap}
        />
      </div>
      <div className="flex items-center gap-3">
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
      <p className="text-xs text-zinc-500">
        Empty input → cap disabled. 0 is a hard cap.
      </p>
    </form>
  );
}

interface FieldProps {
  label: string;
  name: string;
  defaultValue: number | null;
  step?: string;
}

function Field({ label, name, defaultValue, step }: FieldProps) {
  return (
    <label className="flex flex-col gap-1 text-xs text-zinc-400">
      {label}
      <input
        name={name}
        type="number"
        step={step}
        defaultValue={defaultValue ?? ""}
        className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none"
      />
    </label>
  );
}
