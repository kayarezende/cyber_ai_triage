import Link from "next/link";

import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { StatusPill } from "@/components/ui/StatusPill";
import { formatTs, formatUsd, truncate } from "@/lib/format";
import type { InvestigationSummary } from "@/lib/types";

export function InvestigationTable({
  rows,
}: {
  rows: InvestigationSummary[];
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-400">
        No investigations match these filters yet.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded border border-zinc-800 bg-zinc-900">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-zinc-900/80 text-left text-xs uppercase tracking-wide text-zinc-500">
          <tr>
            <th className="px-3 py-2 font-medium">Started</th>
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Verdict</th>
            <th className="px-3 py-2 font-medium">Conf</th>
            <th className="px-3 py-2 font-medium">Approval</th>
            <th className="px-3 py-2 font-medium">Writeback</th>
            <th className="px-3 py-2 font-medium">Cost</th>
            <th className="px-3 py-2 font-medium">Summary</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id}
              className="border-t border-zinc-800 hover:bg-zinc-800/50"
            >
              <td className="px-3 py-2 align-top font-mono text-xs text-zinc-300">
                <Link
                  href={`/investigations/${row.id}`}
                  className="hover:text-zinc-100"
                >
                  {formatTs(row.started_at)}
                </Link>
              </td>
              <td className="px-3 py-2 align-top">
                <SeverityBadge value={row.severity} />
              </td>
              <td className="px-3 py-2 align-top">
                <StatusPill value={row.verdict} />
              </td>
              <td className="px-3 py-2 align-top text-zinc-300">
                {row.confidence === null ? "—" : Math.round(row.confidence * 100)}
              </td>
              <td className="px-3 py-2 align-top">
                <StatusPill value={row.approval_status} />
              </td>
              <td className="px-3 py-2 align-top">
                <StatusPill value={row.writeback_status} />
              </td>
              <td className="px-3 py-2 align-top font-mono text-xs text-zinc-300">
                {formatUsd(row.total_cost_usd)}
              </td>
              <td className="px-3 py-2 align-top text-zinc-300">
                <Link
                  href={`/investigations/${row.id}`}
                  className="hover:underline"
                >
                  {truncate(row.summary_excerpt ?? row.inconclusive_reason, 80) ||
                    "—"}
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
