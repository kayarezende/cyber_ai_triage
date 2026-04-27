import { BudgetsForm } from "@/components/admin/BudgetsForm";
import { ApiError, apiFetch } from "@/lib/api";
import type { TenantBudgets } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function BudgetsPage() {
  let data: TenantBudgets | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<TenantBudgets>("/api/admin/budgets");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        Budgets
      </h1>
      <p className="text-sm text-zinc-400">
        Per-investigation caps gate the LLMRouter pre-call. Empty fields disable
        that cap. The monthly budget is a soft signal surfaced on the usage
        dashboard.
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      {data ? <BudgetsForm budgets={data} /> : null}
    </div>
  );
}
