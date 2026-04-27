const PALETTE: Record<string, string> = {
  new: "bg-zinc-700 text-zinc-100",
  triaging: "bg-sky-700 text-sky-50",
  investigating: "bg-indigo-700 text-indigo-50",
  awaiting_approval: "bg-amber-600 text-amber-50",
  done: "bg-emerald-700 text-emerald-50",
  failed: "bg-red-700 text-red-50",
  inconclusive: "bg-zinc-600 text-zinc-100",
  pending: "bg-amber-600 text-amber-50",
  approved: "bg-emerald-700 text-emerald-50",
  rejected: "bg-red-700 text-red-50",
  auto: "bg-cyan-700 text-cyan-50",
  flagged: "bg-orange-600 text-orange-50",
  succeeded: "bg-emerald-700 text-emerald-50",
  skipped: "bg-zinc-700 text-zinc-100",
};

export function StatusPill({ value }: { value: string | null | undefined }) {
  if (!value) {
    return (
      <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
        —
      </span>
    );
  }
  const className = PALETTE[value] ?? "bg-zinc-700 text-zinc-100";
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${className}`}
    >
      {value}
    </span>
  );
}
