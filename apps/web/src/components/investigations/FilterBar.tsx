"use client";

import { useRouter, useSearchParams } from "next/navigation";

const STATUSES = [
  "",
  "new",
  "triaging",
  "investigating",
  "awaiting_approval",
  "done",
  "failed",
  "inconclusive",
];

const SEVERITIES = ["", "info", "low", "medium", "high", "critical"];

const VERDICTS = [
  "",
  "true_positive",
  "false_positive",
  "benign",
  "inconclusive",
];

const APPROVAL_STATUSES = ["", "pending", "approved", "rejected", "auto"];

interface FilterBarProps {
  current: {
    status?: string;
    severity?: string;
    verdict?: string;
    approval_status?: string;
  };
}

export function FilterBar({ current }: FilterBarProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  function update(key: string, value: string) {
    const params = new URLSearchParams(searchParams);
    if (value) {
      params.set(key, value);
    } else {
      params.delete(key);
    }
    params.delete("cursor"); // any filter change resets pagination
    const qs = params.toString();
    router.push(qs ? `/investigations?${qs}` : "/investigations");
  }

  const baseClass =
    "rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 focus:border-zinc-500 focus:outline-none";

  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400">
      <Select
        label="status"
        value={current.status ?? ""}
        options={STATUSES}
        onChange={(v) => update("status", v)}
        className={baseClass}
      />
      <Select
        label="severity"
        value={current.severity ?? ""}
        options={SEVERITIES}
        onChange={(v) => update("severity", v)}
        className={baseClass}
      />
      <Select
        label="verdict"
        value={current.verdict ?? ""}
        options={VERDICTS}
        onChange={(v) => update("verdict", v)}
        className={baseClass}
      />
      <Select
        label="approval"
        value={current.approval_status ?? ""}
        options={APPROVAL_STATUSES}
        onChange={(v) => update("approval_status", v)}
        className={baseClass}
      />
    </div>
  );
}

interface SelectProps {
  label: string;
  value: string;
  options: readonly string[];
  onChange: (v: string) => void;
  className: string;
}

function Select({ label, value, options, onChange, className }: SelectProps) {
  return (
    <label className="flex items-center gap-1">
      <span className="uppercase tracking-wide text-zinc-500">{label}</span>
      <select
        className={className}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((opt) => (
          <option key={opt || "any"} value={opt}>
            {opt || "any"}
          </option>
        ))}
      </select>
    </label>
  );
}
