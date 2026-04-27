import { SplunkForm } from "@/components/admin/SplunkForm";
import { ApiError, apiFetch } from "@/lib/api";
import type { SplunkConfig } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function SplunkPage() {
  let data: SplunkConfig | null = null;
  let error: string | null = null;
  try {
    data = await apiFetch<SplunkConfig>("/api/admin/splunk");
  } catch (err) {
    error = err instanceof ApiError ? err.message : String(err);
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
        Splunk connection
      </h1>
      <p className="text-sm text-zinc-400">
        Saving a token runs a probe against{" "}
        <code className="font-mono text-xs">/services/server/info</code> on the
        Splunk management port (8089). A typo or revoked token gets caught
        before persistence. Tokens are encrypted at rest with the Fernet key
        from <code className="font-mono text-xs">TENANT_SECRET_KEY</code>.
      </p>
      {error ? (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}
      {data ? <SplunkForm config={data} /> : null}
    </div>
  );
}
