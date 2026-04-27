import Link from "next/link";

import { AuditFilterBar } from "@/components/audit/AuditFilterBar";
import { AuditTable } from "@/components/audit/AuditTable";
import { ApiError, apiFetch } from "@/lib/api";
import type { AuditPage } from "@/lib/types";

interface PageProps {
  searchParams: Promise<Record<string, string | undefined>>;
}

export const dynamic = "force-dynamic";

export default async function AuditExplorerPage({ searchParams }: PageProps) {
  const params = await searchParams;
  let data: AuditPage | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<AuditPage>("/api/audit", {
      searchParams: {
        investigation_id: params.investigation_id,
        action: params.action,
        actor: params.actor,
        cursor: params.cursor,
        limit: 100,
      },
    });
  } catch (err) {
    error =
      err instanceof ApiError ? `API ${err.status}: ${err.path}` : String(err);
  }

  const nextHref = data?.next_cursor
    ? `/audit?${new URLSearchParams({
        ...Object.fromEntries(
          Object.entries(params).filter(
            ([, value]) => value !== undefined,
          ) as [string, string][],
        ),
        cursor: data.next_cursor,
      }).toString()}`
    : null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
            Audit log
          </h1>
          <p className="text-xs text-zinc-500">
            Hash-chained, append-only. Every row carries a recomputed{" "}
            <span className="font-mono">chain_ok</span> verdict.
          </p>
        </div>
        <AuditFilterBar
          current={{
            investigation_id: params.investigation_id,
            action: params.action,
            actor: params.actor,
          }}
        />
      </div>
      {/* Per-row chain_ok already shows integrity at-a-glance. The full
          /api/audit/verify/{id} endpoint exists on the API for deep
          investigations; surface in wk-12 hardening pass. */}
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          Could not load audit log: {error}
        </div>
      ) : null}
      {data ? <AuditTable rows={data.items} /> : null}
      {nextHref ? (
        <div className="flex justify-center">
          <Link
            href={nextHref}
            className="rounded border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            Load more
          </Link>
        </div>
      ) : null}
    </div>
  );
}
