import Link from "next/link";

import { HashCell } from "@/components/ui/HashCell";
import { JsonBlock } from "@/components/ui/JsonBlock";
import { formatTs } from "@/lib/format";
import type { AuditEntry } from "@/lib/types";

export function AuditTable({ rows }: { rows: AuditEntry[] }) {
  if (rows.length === 0) {
    return (
      <div className="rounded border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-400">
        No audit rows match these filters.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded border border-zinc-800 bg-zinc-900">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-zinc-900/80 text-left text-xs uppercase tracking-wide text-zinc-500">
          <tr>
            <th className="px-3 py-2 font-medium">When</th>
            <th className="px-3 py-2 font-medium">Investigation</th>
            <th className="px-3 py-2 font-medium">Actor</th>
            <th className="px-3 py-2 font-medium">Action</th>
            <th className="px-3 py-2 font-medium">Hash</th>
            <th className="px-3 py-2 font-medium">Chain</th>
            <th className="px-3 py-2 font-medium">Details</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-t border-zinc-800 align-top">
              <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">
                {formatTs(row.created_at)}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-zinc-300">
                {row.investigation_id ? (
                  <Link
                    href={`/investigations/${row.investigation_id}`}
                    className="hover:underline"
                  >
                    {row.investigation_id.slice(0, 8)}…
                  </Link>
                ) : (
                  <span className="text-zinc-500">tenant-scope</span>
                )}
              </td>
              <td className="px-3 py-2 text-zinc-300">{row.actor ?? "—"}</td>
              <td className="px-3 py-2 text-zinc-200">{row.action ?? "—"}</td>
              <td className="px-3 py-2"><HashCell value={row.content_hash} /></td>
              <td className="px-3 py-2">
                {row.chain_ok ? (
                  <span
                    className="rounded bg-emerald-700/40 px-1.5 py-0.5 text-[11px] text-emerald-200"
                    title={`prev=${row.previous_hash ?? ""}`}
                  >
                    ✓
                  </span>
                ) : (
                  <span
                    className="rounded bg-red-700/50 px-1.5 py-0.5 text-[11px] text-red-100"
                    title={`prev=${row.previous_hash ?? ""}`}
                  >
                    ✗
                  </span>
                )}
              </td>
              <td className="px-3 py-2 text-zinc-300">
                <details>
                  <summary className="cursor-pointer text-zinc-400">
                    payload
                  </summary>
                  <div className="mt-1">
                    <JsonBlock
                      value={row.details ?? {}}
                      collapsed
                      maxChars={1500}
                    />
                  </div>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
