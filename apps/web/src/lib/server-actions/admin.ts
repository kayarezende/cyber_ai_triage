"use server";

import { revalidatePath } from "next/cache";

import { ApiError, apiFetch } from "@/lib/api";
import type {
  HitlPolicy,
  LlmProvider,
  LlmRoleConfig,
  ProviderKeyStatus,
  TenantBudgets,
  TenantUser,
} from "@/lib/types";

export interface ActionResult<T = void> {
  ok: boolean;
  error?: string;
  detail?: string;
  status?: number;
  data?: T;
}

async function handle<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    const data = await fn();
    return { ok: true, data };
  } catch (err) {
    if (err instanceof ApiError) {
      let detail: string | undefined;
      try {
        const parsed = JSON.parse(err.bodyText);
        detail =
          typeof parsed === "object" && parsed
            ? typeof parsed.detail === "string"
              ? parsed.detail
              : JSON.stringify(parsed.detail)
            : undefined;
      } catch {
        detail = err.bodyText;
      }
      return { ok: false, error: `api_${err.status}`, detail, status: err.status };
    }
    return { ok: false, error: "network_error", detail: String(err) };
  }
}

// ---- LLM roles

// Recombine the provider dropdown + bare model into a `provider:model` ref.
// OpenRouter is left unprefixed so existing/bare rows stay clean.
function composeModelRef(provider: string, model: string): string {
  const m = model.trim();
  if (!provider || provider === "openrouter") return m;
  return `${provider}:${m}`;
}

export async function updateLlmRole(
  role: string,
  formData: FormData,
): Promise<ActionResult<LlmRoleConfig>> {
  const provider = String(formData.get("provider") ?? "openrouter");
  const model = String(formData.get("primary_model") ?? "");
  const body = {
    primary_model: composeModelRef(provider, model),
    fallback_chain: String(formData.get("fallback_chain") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    max_tokens: Number(formData.get("max_tokens") ?? 0),
    temperature: Number(formData.get("temperature") ?? 0),
    timeout_seconds: Number(formData.get("timeout_seconds") ?? 0),
    enabled: formData.get("enabled") === "on",
  };
  const result = await handle(() =>
    apiFetch<LlmRoleConfig>(`/api/admin/llm-roles/${role}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  );
  if (result.ok) revalidatePath("/admin/llm-roles");
  return result;
}

// ---- HITL policies

export async function createHitlPolicy(
  formData: FormData,
): Promise<ActionResult<HitlPolicy>> {
  const raw = String(formData.get("rule_expression") ?? "");
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      ok: false,
      error: "invalid_json",
      detail: `rule_expression must be valid JSON: ${String(err)}`,
    };
  }
  const result = await handle(() =>
    apiFetch<HitlPolicy>("/api/admin/hitl-policies", {
      method: "POST",
      body: JSON.stringify({
        name: String(formData.get("name") ?? ""),
        rule_expression: parsed,
        priority: Number(formData.get("priority") ?? 100),
        enabled: formData.get("enabled") === "on",
      }),
    }),
  );
  if (result.ok) revalidatePath("/admin/hitl-policies");
  return result;
}

export async function deleteHitlPolicy(
  id: string,
): Promise<ActionResult<void>> {
  const result = await handle(() =>
    apiFetch<void>(`/api/admin/hitl-policies/${id}`, { method: "DELETE" }),
  );
  if (result.ok) revalidatePath("/admin/hitl-policies");
  return result;
}

// ---- budgets

export async function updateBudgets(
  formData: FormData,
): Promise<ActionResult<TenantBudgets>> {
  const numOrNull = (key: string): number | null => {
    const value = formData.get(key);
    if (value === null || value === "") return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  };
  const result = await handle(() =>
    apiFetch<TenantBudgets>("/api/admin/budgets", {
      method: "PUT",
      body: JSON.stringify({
        max_concurrent_investigations: numOrNull("max_concurrent_investigations"),
        monthly_llm_budget_usd: numOrNull("monthly_llm_budget_usd"),
        per_investigation_budget_usd: numOrNull("per_investigation_budget_usd"),
        per_investigation_token_cap: numOrNull("per_investigation_token_cap"),
      }),
    }),
  );
  if (result.ok) revalidatePath("/admin/budgets");
  return result;
}

// ---- splunk

export async function updateSplunkConfig(
  formData: FormData,
): Promise<ActionResult<unknown>> {
  const body: Record<string, unknown> = {
    splunk_host: String(formData.get("splunk_host") ?? ""),
    writeback_mode: String(formData.get("writeback_mode") ?? "hec_only"),
    skip_probe: formData.get("skip_probe") === "on",
  };
  const token = String(formData.get("splunk_token") ?? "").trim();
  const hec = String(formData.get("splunk_hec_token") ?? "").trim();
  if (token) body.splunk_token = token;
  if (hec) body.splunk_hec_token = hec;
  const result = await handle(() =>
    apiFetch<unknown>("/api/admin/splunk", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  );
  if (result.ok) revalidatePath("/admin/splunk");
  return result;
}

// ---- users

export async function inviteUser(
  formData: FormData,
): Promise<ActionResult<TenantUser>> {
  const result = await handle(() =>
    apiFetch<TenantUser>("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        email: String(formData.get("email") ?? ""),
        role: String(formData.get("role") ?? "analyst"),
      }),
    }),
  );
  if (result.ok) revalidatePath("/admin/users");
  return result;
}

export async function updateUserRole(
  userId: string,
  formData: FormData,
): Promise<ActionResult<TenantUser>> {
  const result = await handle(() =>
    apiFetch<TenantUser>(`/api/admin/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify({ role: String(formData.get("role") ?? "analyst") }),
    }),
  );
  if (result.ok) revalidatePath("/admin/users");
  return result;
}

// ---- provider keys

export async function setProviderKey(
  provider: LlmProvider,
  formData: FormData,
): Promise<ActionResult<ProviderKeyStatus>> {
  const apiKey = String(formData.get("api_key") ?? "").trim();
  if (!apiKey) {
    return { ok: false, error: "empty_key", detail: "Enter an API key to save." };
  }
  const result = await handle(() =>
    apiFetch<ProviderKeyStatus>(`/api/admin/provider-keys/${provider}`, {
      method: "PUT",
      body: JSON.stringify({ api_key: apiKey }),
    }),
  );
  if (result.ok) revalidatePath("/admin/provider-keys");
  return result;
}

export async function deleteProviderKey(
  provider: LlmProvider,
): Promise<ActionResult<void>> {
  const result = await handle(() =>
    apiFetch<void>(`/api/admin/provider-keys/${provider}`, { method: "DELETE" }),
  );
  if (result.ok) revalidatePath("/admin/provider-keys");
  return result;
}
