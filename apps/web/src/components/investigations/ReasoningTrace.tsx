import { JsonBlock } from "@/components/ui/JsonBlock";
import type { EvidenceManifest, TimelineEntry } from "@/lib/types";

interface TraceStep {
  index: number;
  kind: "agent" | "tool" | "audit";
  label: string;
  ts: string | null;
  payload: unknown;
}

export function ReasoningTrace({
  manifest,
  timeline,
}: {
  manifest: EvidenceManifest | null;
  timeline: TimelineEntry[];
}) {
  const steps = mergeSteps(manifest, timeline);

  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <header className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
          Reasoning Trace
        </h2>
        <span className="text-xs text-zinc-500">{steps.length} steps</span>
      </header>
      {steps.length === 0 ? (
        <p className="text-sm text-zinc-500">
          No reasoning trace recorded yet — manifest may still be uploading.
        </p>
      ) : (
        <ol className="space-y-2">
          {steps.map((step) => (
            <li key={`${step.kind}-${step.index}`} className="rounded border border-zinc-800">
              <details>
                <summary className="cursor-pointer px-3 py-2 text-sm">
                  <span className="mr-2 font-mono text-[11px] text-zinc-500">
                    [{step.kind}]
                  </span>
                  <span className="text-zinc-200">{step.label}</span>
                  <span className="ml-2 font-mono text-[11px] text-zinc-500">
                    {step.ts ?? ""}
                  </span>
                </summary>
                <div className="border-t border-zinc-800 p-3">
                  <JsonBlock value={step.payload} collapsed maxChars={2500} />
                </div>
              </details>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function mergeSteps(
  manifest: EvidenceManifest | null,
  timeline: TimelineEntry[],
): TraceStep[] {
  const out: TraceStep[] = [];
  let idx = 0;
  for (const turn of manifest?.agent_turns ?? []) {
    const role =
      typeof turn === "object" && turn !== null
        ? ((turn as Record<string, unknown>).role as string | undefined)
        : undefined;
    const label = role ? `agent · ${role}` : "agent turn";
    out.push({
      index: idx++,
      kind: "agent",
      label,
      ts: null,
      payload: turn,
    });
  }
  for (const entry of timeline) {
    if (!entry.action) continue;
    out.push({
      index: idx++,
      kind: entry.action.startsWith("tool") ? "tool" : "audit",
      label: entry.action,
      ts: entry.created_at,
      payload: entry.details,
    });
  }
  return out;
}
