"use server";

import { revalidatePath } from "next/cache";

import { ApiError, apiFetch } from "@/lib/api";

export interface ApprovalActionResult {
  ok: boolean;
  error?: string;
  detail?: string;
  status?: number;
}

interface ApprovalBody {
  approved: boolean;
  notes: string;
  analyst_id?: string | null;
}

async function postApproval(
  investigationId: string,
  body: ApprovalBody,
): Promise<ApprovalActionResult> {
  try {
    await apiFetch(`/api/approvals/${investigationId}`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    revalidatePath(`/investigations/${investigationId}`);
    revalidatePath("/investigations");
    return { ok: true };
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
      return {
        ok: false,
        error: `api_${err.status}`,
        detail,
        status: err.status,
      };
    }
    return { ok: false, error: "network_error", detail: String(err) };
  }
}

export async function approveInvestigation(
  investigationId: string,
  formData: FormData,
): Promise<ApprovalActionResult> {
  const notes = String(formData.get("notes") ?? "");
  return postApproval(investigationId, { approved: true, notes });
}

export async function rejectInvestigation(
  investigationId: string,
  formData: FormData,
): Promise<ApprovalActionResult> {
  const notes = String(formData.get("notes") ?? "");
  return postApproval(investigationId, { approved: false, notes });
}
