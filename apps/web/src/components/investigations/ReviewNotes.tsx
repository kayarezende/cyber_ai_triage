import { StatusPill } from "@/components/ui/StatusPill";
import type { InvestigationDetail } from "@/lib/types";

export function ReviewNotes({ inv }: { inv: InvestigationDetail }) {
  const meta = inv.review_metadata ?? {};
  const flagged: unknown = (meta as Record<string, unknown>).flagged_claims;
  const flaggedClaims = Array.isArray(flagged) ? (flagged as string[]) : [];

  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <header className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
          Review
        </h2>
        <StatusPill value={inv.review_status} />
      </header>
      {inv.review_notes ? (
        <p className="text-sm leading-6 text-zinc-200">{inv.review_notes}</p>
      ) : (
        <p className="text-sm text-zinc-500">No review notes recorded.</p>
      )}
      {flaggedClaims.length > 0 ? (
        <div className="mt-3">
          <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
            Flagged claims
          </h3>
          <ul className="mt-1 list-inside list-disc space-y-1 text-xs text-zinc-300">
            {flaggedClaims.map((claim, idx) => (
              <li key={idx}>{claim}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
