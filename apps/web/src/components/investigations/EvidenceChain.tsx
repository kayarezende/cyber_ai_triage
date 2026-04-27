import { JsonBlock } from "@/components/ui/JsonBlock";
import { formatTs } from "@/lib/format";
import type { EvidenceManifest } from "@/lib/types";

export function EvidenceChain({ manifest }: { manifest: EvidenceManifest | null }) {
  const tools = manifest?.tool_calls ?? [];
  const attempts = manifest?.attempts ?? [];

  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
        Evidence Chain
      </h2>
      {tools.length === 0 ? (
        <p className="text-sm text-zinc-500">
          No tool invocations recorded in the manifest yet.
        </p>
      ) : (
        <div className="overflow-hidden rounded border border-zinc-800">
          <table className="w-full border-collapse text-xs">
            <thead className="bg-zinc-900/80 text-left uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-2 py-1.5 font-medium">When</th>
                <th className="px-2 py-1.5 font-medium">Tool</th>
                <th className="px-2 py-1.5 font-medium">Latency</th>
                <th className="px-2 py-1.5 font-medium">Result</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((entry, idx) => {
                const e = entry as Record<string, unknown>;
                const detail = e.details as Record<string, unknown> | undefined;
                const args = (detail?.args as Record<string, unknown>) ?? {};
                const summary =
                  (detail?.result_summary as string | undefined) ??
                  (e.result_summary as string | undefined) ??
                  "";
                const latency =
                  (detail?.latency_ms as number | undefined) ??
                  (e.latency_ms as number | undefined) ??
                  null;
                const toolName =
                  (detail?.tool_name as string | undefined) ??
                  (e.tool_name as string | undefined) ??
                  "—";
                const ts = (e.created_at as string | undefined) ?? null;
                return (
                  <tr key={idx} className="border-t border-zinc-800 align-top">
                    <td className="px-2 py-1.5 font-mono text-[11px] text-zinc-400">
                      {formatTs(ts)}
                    </td>
                    <td className="px-2 py-1.5 text-zinc-200">{toolName}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-zinc-400">
                      {latency === null ? "—" : `${latency}ms`}
                    </td>
                    <td className="px-2 py-1.5 text-zinc-300">
                      <details>
                        <summary className="cursor-pointer text-zinc-200">
                          {summary
                            ? summary.slice(0, 80) +
                              (summary.length > 80 ? "…" : "")
                            : "(no summary)"}
                        </summary>
                        <div className="mt-2 grid gap-2">
                          <div>
                            <div className="text-[11px] uppercase text-zinc-500">
                              args
                            </div>
                            <JsonBlock value={args} collapsed maxChars={1200} />
                          </div>
                          {summary ? (
                            <div>
                              <div className="text-[11px] uppercase text-zinc-500">
                                result
                              </div>
                              <pre className="rounded border border-zinc-800 bg-zinc-900/60 p-2 font-mono text-[11px] text-zinc-200 whitespace-pre-wrap break-all">
                                {summary}
                              </pre>
                            </div>
                          ) : null}
                        </div>
                      </details>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {attempts.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-zinc-500">
            LLM attempts ({attempts.length})
          </h3>
          <JsonBlock value={attempts} collapsed maxChars={1500} />
        </div>
      ) : null}
    </section>
  );
}
