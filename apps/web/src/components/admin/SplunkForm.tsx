"use client";

import { useState, useTransition } from "react";

import { updateSplunkConfig } from "@/lib/server-actions/admin";
import type { SplunkConfig } from "@/lib/types";

interface Props {
  config: SplunkConfig;
}

export function SplunkForm({ config }: Props) {
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
          const result = await updateSplunkConfig(formData);
          if (result.ok) {
            setMessage("Saved + probed.");
          } else {
            setError(result.detail ?? result.error ?? "save failed");
          }
        });
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        splunk_host
        <input
          name="splunk_host"
          required
          defaultValue={config.splunk_host ?? ""}
          placeholder="splunk.example.local"
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        writeback_mode
        <select
          name="writeback_mode"
          defaultValue={config.writeback_mode}
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
        >
          <option value="hec_only">hec_only (base Splunk Enterprise)</option>
          <option value="dual">dual (Splunk ES required)</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        splunk_token (management) — leave blank to keep current
        <input
          name="splunk_token"
          type="password"
          autoComplete="off"
          placeholder={
            config.has_management_token ? "•••• stored" : "not configured"
          }
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-zinc-400">
        splunk_hec_token — leave blank to keep current
        <input
          name="splunk_hec_token"
          type="password"
          autoComplete="off"
          placeholder={config.has_hec_token ? "•••• stored" : "not configured"}
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
        />
      </label>
      <label className="flex items-center gap-2 text-xs text-zinc-400">
        <input type="checkbox" name="skip_probe" className="h-3 w-3" />
        skip_probe (use when Splunk box is offline at edit time)
      </label>
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className="rounded bg-zinc-700 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-600 disabled:opacity-60"
        >
          {pending ? "Saving…" : "Save & probe"}
        </button>
        {message ? (
          <span className="text-xs text-emerald-400">{message}</span>
        ) : null}
        {error ? <span className="text-xs text-red-400">{error}</span> : null}
      </div>
    </form>
  );
}
