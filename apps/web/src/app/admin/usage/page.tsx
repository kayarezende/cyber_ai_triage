import { ApiError, apiFetch } from "@/lib/api";
import type { UsageSummary } from "@/lib/types";

export const dynamic = "force-dynamic";

interface PageProps {
  searchParams: Promise<{ months_back?: string }>;
}

const RANGE_OPTIONS = [1, 3, 6, 12];

export default async function UsagePage({ searchParams }: PageProps) {
  const params = await searchParams;
  const monthsBack = clampRange(params.months_back);

  let data: UsageSummary | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<UsageSummary>("/api/admin/usage", {
      searchParams: { months_back: monthsBack },
    });
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
            Usage
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Per-month tokens, cost, and attempt counts grouped by role + model.
            Driven off the per-attempt audit ledger (ADR-0015) — failed
            attempts that consumed tokens are counted toward spend.
          </p>
        </div>
        <RangePicker active={monthsBack} />
      </div>

      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      {data ? <SummaryCards data={data} /> : null}
      {data ? <StatusBreakdown data={data} /> : null}
      {data ? <UsageTable data={data} /> : null}
    </div>
  );
}

function clampRange(raw: string | undefined): number {
  const n = Number(raw ?? 3);
  if (!Number.isFinite(n) || n < 1) return 3;
  if (n > 24) return 24;
  return Math.floor(n);
}

function RangePicker({ active }: { active: number }) {
  return (
    <nav className="flex items-center gap-1 text-xs text-zinc-400">
      <span className="mr-2 uppercase tracking-wide">Window</span>
      {RANGE_OPTIONS.map((m) => (
        <a
          key={m}
          href={`/admin/usage?months_back=${m}`}
          className={
            m === active
              ? "rounded bg-zinc-800 px-2 py-1 text-zinc-100"
              : "rounded px-2 py-1 hover:bg-zinc-900 hover:text-zinc-100"
          }
        >
          {m}m
        </a>
      ))}
    </nav>
  );
}

function SummaryCards({ data }: { data: UsageSummary }) {
  const cards = [
    { label: "Total cost", value: `$${data.total_cost_usd.toFixed(4)}` },
    { label: "Attempts", value: data.total_attempts.toLocaleString() },
    {
      label: "Successes",
      value: `${data.total_successes.toLocaleString()} / ${data.total_attempts.toLocaleString()}`,
    },
    {
      label: "Input tokens",
      value: data.total_input_tokens.toLocaleString(),
    },
    {
      label: "Output tokens",
      value: data.total_output_tokens.toLocaleString(),
    },
    {
      label: "Cached tokens",
      value: data.total_cached_tokens.toLocaleString(),
    },
  ];
  return (
    <div className="flex flex-wrap gap-3">
      {cards.map((c) => (
        <div
          key={c.label}
          className="min-w-[140px] rounded border border-zinc-800 bg-zinc-900 px-4 py-3"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500">
            {c.label}
          </div>
          <div className="mt-1 font-mono text-lg text-zinc-100">{c.value}</div>
        </div>
      ))}
    </div>
  );
}

function StatusBreakdown({ data }: { data: UsageSummary }) {
  if (data.by_status.length === 0) return null;
  return (
    <div className="rounded border border-zinc-800 bg-zinc-900 p-3">
      <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">
        By status
      </h2>
      <div className="flex flex-wrap gap-3 text-xs">
        {data.by_status.map((s) => (
          <span
            key={s.status}
            className={
              s.status === "success"
                ? "rounded bg-emerald-900 px-2 py-1 font-mono text-emerald-200"
                : "rounded bg-red-950 px-2 py-1 font-mono text-red-200"
            }
          >
            {s.status} · {s.count.toLocaleString()}
          </span>
        ))}
      </div>
    </div>
  );
}

function UsageTable({ data }: { data: UsageSummary }) {
  if (data.rows.length === 0) {
    return (
      <p className="text-sm text-zinc-500">
        No usage rows in the selected window.
      </p>
    );
  }
  return (
    <table className="w-full border-collapse text-xs">
      <thead className="text-[11px] uppercase tracking-wide text-zinc-500">
        <tr>
          <th className="border-b border-zinc-800 py-2 text-left">Month</th>
          <th className="border-b border-zinc-800 py-2 text-left">Role</th>
          <th className="border-b border-zinc-800 py-2 text-left">Model</th>
          <th className="border-b border-zinc-800 py-2 text-right">Attempts</th>
          <th className="border-b border-zinc-800 py-2 text-right">OK / Fail</th>
          <th className="border-b border-zinc-800 py-2 text-right">In tok</th>
          <th className="border-b border-zinc-800 py-2 text-right">Out tok</th>
          <th className="border-b border-zinc-800 py-2 text-right">Cached</th>
          <th className="border-b border-zinc-800 py-2 text-right">Cost</th>
        </tr>
      </thead>
      <tbody>
        {data.rows.map((r, i) => (
          <tr
            key={`${r.month}|${r.role}|${r.model_requested}|${i}`}
            className="border-b border-zinc-900"
          >
            <td className="py-2 font-mono text-zinc-300">{r.month}</td>
            <td className="py-2 font-mono text-zinc-300">{r.role}</td>
            <td className="py-2 font-mono text-zinc-200">{r.model_requested}</td>
            <td className="py-2 text-right font-mono text-zinc-200">
              {r.attempts.toLocaleString()}
            </td>
            <td className="py-2 text-right font-mono">
              <span className="text-emerald-300">{r.successes}</span>
              <span className="text-zinc-600"> / </span>
              <span className={r.failures > 0 ? "text-red-300" : "text-zinc-500"}>
                {r.failures}
              </span>
            </td>
            <td className="py-2 text-right font-mono text-zinc-300">
              {r.input_tokens.toLocaleString()}
            </td>
            <td className="py-2 text-right font-mono text-zinc-300">
              {r.output_tokens.toLocaleString()}
            </td>
            <td className="py-2 text-right font-mono text-zinc-400">
              {r.cached_tokens.toLocaleString()}
            </td>
            <td className="py-2 text-right font-mono text-zinc-200">
              ${r.cost_usd.toFixed(4)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
