import { ENTERPRISE_TACTICS, attackUrl } from "@/lib/mitre";
import type { MitreTechnique } from "@/lib/types";

export function MitreHeatmap({
  techniques,
}: {
  techniques: MitreTechnique[];
}) {
  if (techniques.length === 0) {
    return (
      <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-zinc-400">
          MITRE ATT&amp;CK
        </h2>
        <p className="text-sm text-zinc-500">
          No techniques observed in this investigation.
        </p>
      </section>
    );
  }

  // Group observed techniques per tactic. A technique can map to multiple.
  const byTactic = new Map<string, MitreTechnique[]>();
  for (const t of techniques) {
    const tactics = t.tactic_ids.length > 0 ? t.tactic_ids : ["unmapped"];
    for (const tac of tactics) {
      const arr = byTactic.get(tac) ?? [];
      arr.push(t);
      byTactic.set(tac, arr);
    }
  }
  const observedTactics = ENTERPRISE_TACTICS.filter((t) => byTactic.has(t.id));
  const unmappedCount = byTactic.get("unmapped")?.length ?? 0;

  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <header className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
          MITRE ATT&amp;CK
        </h2>
        <span className="text-xs text-zinc-500">
          {techniques.length} technique{techniques.length === 1 ? "" : "s"}
        </span>
      </header>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {observedTactics.map((tac) => (
          <div key={tac.id} className="rounded border border-zinc-800 p-2">
            <div className="text-xs font-medium uppercase tracking-wide text-zinc-300">
              {tac.name}
            </div>
            <ul className="mt-1 space-y-0.5">
              {(byTactic.get(tac.id) ?? []).map((t) => (
                <li key={`${tac.id}-${t.technique_id}`}>
                  <a
                    href={attackUrl(t.technique_id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block rounded bg-amber-600/30 px-2 py-0.5 text-xs text-amber-100 hover:bg-amber-600/50"
                  >
                    <span className="font-mono">{t.technique_id}</span>
                    {t.name ? ` — ${t.name}` : ""}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {unmappedCount > 0 ? (
          <div className="rounded border border-zinc-800 p-2 text-xs text-zinc-400">
            <div className="font-medium uppercase tracking-wide text-zinc-300">
              Unmapped
            </div>
            <p className="mt-1">{unmappedCount} technique(s) without tactic.</p>
          </div>
        ) : null}
      </div>
    </section>
  );
}
