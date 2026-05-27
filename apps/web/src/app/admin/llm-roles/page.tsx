import { LlmRoleForm } from "@/components/admin/LlmRoleForm";
import { ApiError, apiFetch } from "@/lib/api";
import type { LlmRoleListResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function LlmRolesPage() {
  let data: LlmRoleListResponse | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<LlmRoleListResponse>("/api/admin/llm-roles");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        LLM role config
      </h1>
      <p className="text-sm text-zinc-400">
        Choose a provider and model per role. Keys are managed on the{" "}
        <code className="font-mono text-xs">Provider keys</code> page. Fields map
        to what the LLMRouter consumes (<code className="font-mono text-xs">primary_model</code>,{" "}
        <code className="font-mono text-xs">fallback_chain</code>,{" "}
        <code className="font-mono text-xs">max_tokens</code>,{" "}
        <code className="font-mono text-xs">temperature</code>,{" "}
        <code className="font-mono text-xs">timeout_seconds</code>,{" "}
        <code className="font-mono text-xs">enabled</code>). Changes take
        effect on the next investigation.
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      <div className="flex flex-col gap-3">
        {data?.items.map((role) => (
          <LlmRoleForm key={role.role} role={role} />
        ))}
      </div>
    </div>
  );
}
