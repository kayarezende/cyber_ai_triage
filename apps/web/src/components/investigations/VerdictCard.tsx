import Link from "next/link";

import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { StatusPill } from "@/components/ui/StatusPill";
import { formatTs, formatUsd } from "@/lib/format";
import type { InvestigationDetail } from "@/lib/types";

export function VerdictCard({ inv }: { inv: InvestigationDetail }) {
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <header className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
          Verdict
        </h2>
        <Link
          href={`/investigations/${inv.id}/replay`}
          className="rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-300 hover:bg-zinc-800"
        >
          replay
        </Link>
      </header>
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill value={inv.verdict} />
        <SeverityBadge value={inv.severity} />
        <span className="text-xs text-zinc-400">
          confidence {inv.confidence === null ? "—" : Math.round(inv.confidence * 100)}
        </span>
      </div>
      <p className="mt-3 text-sm leading-6 text-zinc-200">
        {inv.summary ?? inv.inconclusive_reason ?? "No summary recorded yet."}
      </p>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs text-zinc-400">
        <Stat label="started" value={formatTs(inv.started_at)} mono />
        <Stat label="completed" value={formatTs(inv.completed_at)} mono />
        <Stat label="incident" value={inv.incident_status ?? "—"} />
        <Stat label="approval" value={inv.approval_status ?? "—"} />
        <Stat label="review" value={inv.review_status ?? "—"} />
        <Stat label="writeback" value={inv.writeback_status ?? "—"} />
        <Stat
          label="cost"
          value={formatUsd(inv.total_cost_usd)}
          mono
        />
        <Stat
          label="tokens"
          value={`${inv.total_input_tokens ?? 0} / ${inv.total_output_tokens ?? 0}`}
          mono
        />
        <Stat
          label="thread"
          value={inv.langgraph_thread_id ?? "—"}
          mono
        />
      </dl>
    </section>
  );
}

function Stat({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="uppercase tracking-wide text-zinc-500">{label}</dt>
      <dd className={`text-zinc-200 ${mono ? "font-mono text-[11px]" : ""}`}>
        {value}
      </dd>
    </div>
  );
}
