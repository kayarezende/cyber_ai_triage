"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

interface FilterState {
  investigation_id?: string;
  action?: string;
  actor?: string;
}

export function AuditFilterBar({ current }: { current: FilterState }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [investigationId, setInvestigationId] = useState(
    current.investigation_id ?? "",
  );
  const [action, setAction] = useState(current.action ?? "");
  const [actor, setActor] = useState(current.actor ?? "");

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    const params = new URLSearchParams(searchParams);
    setOrDelete(params, "investigation_id", investigationId);
    setOrDelete(params, "action", action);
    setOrDelete(params, "actor", actor);
    params.delete("cursor");
    const qs = params.toString();
    router.push(qs ? `/audit?${qs}` : "/audit");
  }

  return (
    <form
      onSubmit={applyFilters}
      className="flex flex-wrap items-end gap-2 text-xs text-zinc-400"
    >
      <Input
        label="investigation_id"
        value={investigationId}
        onChange={setInvestigationId}
        placeholder="UUID"
      />
      <Input
        label="action"
        value={action}
        onChange={setAction}
        placeholder="e.g. tool_call"
      />
      <Input
        label="actor"
        value={actor}
        onChange={setActor}
        placeholder="e.g. orchestrator:investigation"
      />
      <button
        type="submit"
        className="rounded border border-zinc-700 bg-zinc-900 px-3 py-1 text-zinc-200 hover:bg-zinc-800"
      >
        apply
      </button>
    </form>
  );
}

function setOrDelete(
  params: URLSearchParams,
  key: string,
  value: string,
): void {
  const trimmed = value.trim();
  if (trimmed) {
    params.set(key, trimmed);
  } else {
    params.delete(key);
  }
}

function Input({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-0.5">
      <span className="uppercase tracking-wide text-zinc-500">{label}</span>
      <input
        className="w-56 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-100 focus:border-zinc-500 focus:outline-none"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </label>
  );
}
