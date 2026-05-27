import { ProviderKeyForm } from "@/components/admin/ProviderKeyForm";
import { ApiError, apiFetch } from "@/lib/api";
import type { ProviderKeyListResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function ProviderKeysPage() {
  let data: ProviderKeyListResponse | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<ProviderKeyListResponse>("/api/admin/provider-keys");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        Provider API keys
      </h1>
      <p className="text-sm text-zinc-400">
        Per-provider LLM API keys, encrypted at rest with the Fernet key from{" "}
        <code className="font-mono text-xs">TENANT_SECRET_KEY</code>. Keys are
        write-only — only a masked last-4 hint is shown, never the key itself.
        The router uses whichever provider a role&apos;s model resolves to
        (set models on the{" "}
        <code className="font-mono text-xs">LLM roles</code> page).
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      <div className="flex flex-col gap-3">
        {data?.items.map((status) => (
          <ProviderKeyForm key={status.provider} status={status} />
        ))}
      </div>
    </div>
  );
}
