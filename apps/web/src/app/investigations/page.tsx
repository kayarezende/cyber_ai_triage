import Link from "next/link";

import { FilterBar } from "@/components/investigations/FilterBar";
import { InvestigationTable } from "@/components/investigations/InvestigationTable";
import { ApiError, apiFetch } from "@/lib/api";
import type { InvestigationListResponse } from "@/lib/types";

interface PageProps {
  searchParams: Promise<Record<string, string | undefined>>;
}

export const dynamic = "force-dynamic";

export default async function InvestigationsPage({ searchParams }: PageProps) {
  const params = await searchParams;
  let data: InvestigationListResponse | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<InvestigationListResponse>("/api/investigations", {
      searchParams: {
        status: params.status,
        severity: params.severity,
        verdict: params.verdict,
        approval_status: params.approval_status,
        cursor: params.cursor,
        limit: 50,
      },
    });
  } catch (err) {
    error =
      err instanceof ApiError ? `API ${err.status}: ${err.path}` : String(err);
  }

  const nextHref = data?.next_cursor
    ? `/investigations?${new URLSearchParams({
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
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
          Investigations
        </h1>
        <FilterBar
          current={{
            status: params.status,
            severity: params.severity,
            verdict: params.verdict,
            approval_status: params.approval_status,
          }}
        />
      </div>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          Could not load investigations: {error}
        </div>
      ) : null}
      {data ? <InvestigationTable rows={data.items} /> : null}
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
