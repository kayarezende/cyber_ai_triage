import Link from "next/link";
import { notFound } from "next/navigation";

import { ApprovalBar } from "@/components/investigations/ApprovalBar";
import { EvidenceChain } from "@/components/investigations/EvidenceChain";
import { MitreHeatmap } from "@/components/investigations/MitreHeatmap";
import { ReasoningTrace } from "@/components/investigations/ReasoningTrace";
import { ReviewNotes } from "@/components/investigations/ReviewNotes";
import { VerdictCard } from "@/components/investigations/VerdictCard";
import { JsonBlock } from "@/components/ui/JsonBlock";
import { ApiError, NotFoundError, apiFetch } from "@/lib/api";
import type {
  EvidenceManifest,
  InvestigationDetail,
  TimelineResponse,
} from "@/lib/types";

interface PageProps {
  params: Promise<{ id: string }>;
}

export const dynamic = "force-dynamic";

export default async function InvestigationDetailPage({ params }: PageProps) {
  const { id } = await params;

  let detail: InvestigationDetail;
  try {
    detail = await apiFetch<InvestigationDetail>(`/api/investigations/${id}`);
  } catch (err) {
    if (err instanceof NotFoundError) {
      notFound();
    }
    if (err instanceof ApiError) {
      return (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          API error {err.status}: {err.path}
        </div>
      );
    }
    throw err;
  }

  const [manifestResult, timelineResult] = await Promise.allSettled([
    apiFetch<EvidenceManifest>(`/api/investigations/${id}/manifest`),
    apiFetch<TimelineResponse>(`/api/investigations/${id}/timeline`),
  ]);

  const manifest =
    manifestResult.status === "fulfilled" ? manifestResult.value : null;
  const timeline =
    timelineResult.status === "fulfilled" ? timelineResult.value.items : [];

  return (
    <div className="flex flex-col gap-4">
      <Header inv={detail} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)]">
        <div className="flex flex-col gap-4">
          <VerdictCard inv={detail} />
          <MitreHeatmap techniques={detail.mitre_resolved} />
          <ReviewNotes inv={detail} />
          <ApprovalBar
            investigationId={detail.id}
            approvalStatus={detail.approval_status}
            decisionSubmitted={detail.decision_submitted}
          />
          <DetectionRules inv={detail} />
        </div>
        <div className="flex flex-col gap-4">
          <ReasoningTrace manifest={manifest} timeline={timeline} />
          <EvidenceChain manifest={manifest} />
          <WritebackCard inv={detail} />
          <RawSurfaces inv={detail} manifest={manifest} />
        </div>
      </div>
    </div>
  );
}

function Header({ inv }: { inv: InvestigationDetail }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <Link
          href="/investigations"
          className="text-xs text-zinc-500 hover:text-zinc-300"
        >
          ← all investigations
        </Link>
        <h1 className="mt-1 font-mono text-lg text-zinc-100">{inv.id}</h1>
        <p className="mt-1 text-xs text-zinc-500">
          incident{" "}
          <span className="font-mono">{inv.incident_id}</span> · siem{" "}
          {inv.siem_source ?? "—"} · notable{" "}
          <span className="font-mono">{inv.siem_notable_id ?? "—"}</span>
        </p>
      </div>
    </div>
  );
}

function DetectionRules({ inv }: { inv: InvestigationDetail }) {
  if (!inv.detection_rule_matches || inv.detection_rule_matches.length === 0) {
    return null;
  }
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
        Detection Rule Matches
      </h2>
      <ul className="space-y-1 text-xs text-zinc-300">
        {inv.detection_rule_matches.map((match, idx) => {
          const m = match as Record<string, unknown>;
          const name = (m.rule_name as string | undefined) ?? "(unnamed)";
          const ruleId = (m.rule_id as string | undefined) ?? "—";
          const sevOverride = m.severity_override as string | undefined;
          return (
            <li key={idx} className="rounded border border-zinc-800 px-2 py-1">
              <span className="font-medium text-zinc-100">{name}</span>{" "}
              <span className="font-mono text-[11px] text-zinc-500">
                {ruleId}
              </span>
              {sevOverride ? (
                <span className="ml-2 rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] uppercase text-amber-300">
                  ⇒ {sevOverride}
                </span>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function WritebackCard({ inv }: { inv: InvestigationDetail }) {
  if (!inv.writeback_attempts || inv.writeback_attempts.length === 0) {
    return null;
  }
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
        Writeback Attempts
      </h2>
      <JsonBlock value={inv.writeback_attempts} collapsed={false} />
    </section>
  );
}

function RawSurfaces({
  inv,
  manifest,
}: {
  inv: InvestigationDetail;
  manifest: EvidenceManifest | null;
}) {
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">
        Raw payloads
      </h2>
      <div className="grid gap-3 text-xs">
        <details>
          <summary className="cursor-pointer text-zinc-300">
            Source notable (OCSF)
          </summary>
          <div className="mt-2">
            <JsonBlock value={inv.ocsf_normalized} collapsed maxChars={2500} />
          </div>
        </details>
        {inv.ocsf_output ? (
          <details>
            <summary className="cursor-pointer text-zinc-300">
              Final OCSF output
            </summary>
            <div className="mt-2">
              <JsonBlock value={inv.ocsf_output} collapsed maxChars={2500} />
            </div>
          </details>
        ) : null}
        {manifest ? (
          <details>
            <summary className="cursor-pointer text-zinc-300">
              Evidence manifest
            </summary>
            <div className="mt-2">
              <JsonBlock value={manifest} collapsed maxChars={3000} />
            </div>
          </details>
        ) : null}
      </div>
    </section>
  );
}
