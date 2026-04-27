import Link from "next/link";

import type { CheckpointSummary } from "@/lib/types";

export function CheckpointStepper({
  investigationId,
  items,
  activeId,
}: {
  investigationId: string;
  items: CheckpointSummary[];
  activeId: string | null;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded border border-zinc-800 bg-zinc-900 p-4 text-sm text-zinc-400">
        No checkpoints recorded yet — investigation may not have started.
      </div>
    );
  }
  return (
    <ol className="rounded border border-zinc-800 bg-zinc-900">
      {items.map((cp, idx) => {
        const active = cp.checkpoint_id === activeId;
        return (
          <li
            key={cp.checkpoint_id}
            className={`border-b border-zinc-800 last:border-b-0 ${
              active ? "bg-zinc-800/70" : ""
            }`}
          >
            <Link
              href={`/investigations/${investigationId}/replay?cp=${encodeURIComponent(cp.checkpoint_id)}`}
              className="block px-3 py-2 hover:bg-zinc-800"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-zinc-300">
                  step {cp.step ?? idx}
                </span>
                {cp.has_interrupt ? (
                  <span className="rounded bg-amber-700 px-1.5 py-0.5 text-[10px] uppercase text-amber-50">
                    interrupt
                  </span>
                ) : null}
              </div>
              <div className="mt-0.5 text-xs text-zinc-200">
                {cp.node_writes.join(", ") || "(no writes)"}
              </div>
              <div className="font-mono text-[10px] text-zinc-500">
                {cp.ts ?? ""}
              </div>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
