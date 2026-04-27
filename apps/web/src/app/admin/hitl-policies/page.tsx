import { CreatePolicyForm } from "@/components/admin/CreatePolicyForm";
import { PolicyRow } from "@/components/admin/PolicyRow";
import { ApiError, apiFetch } from "@/lib/api";
import type { HitlPolicyListResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function HitlPoliciesPage() {
  let data: HitlPolicyListResponse | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<HitlPolicyListResponse>("/api/admin/hitl-policies");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        HITL policies
      </h1>
      <p className="text-sm text-zinc-400">
        JSONB rule expressions evaluated by the orchestrator before
        auto-approving an investigation. Highest-priority enabled policy
        visible to the tenant wins; tenant rules beat globals at the same
        priority. Default fallback is{" "}
        <code className="font-mono text-xs">{"{op: always_true}"}</code>
        (require human approval).
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      <div className="flex flex-col gap-2">
        {data?.items.map((policy) => (
          <PolicyRow key={policy.id} policy={policy} />
        ))}
        {data && data.items.length === 0 ? (
          <p className="text-sm text-zinc-500">No policies configured.</p>
        ) : null}
      </div>
      <h2 className="mt-2 text-sm font-semibold tracking-tight text-zinc-200">
        Add policy
      </h2>
      <CreatePolicyForm />
    </div>
  );
}
