"use client";

import { useState, useTransition } from "react";

import {
  approveInvestigation,
  rejectInvestigation,
} from "@/lib/server-actions/approvals";
import type { ApprovalActionResult } from "@/lib/server-actions/approvals";

export function ApprovalBar({
  investigationId,
  approvalStatus,
  decisionSubmitted,
}: {
  investigationId: string;
  approvalStatus: string | null;
  decisionSubmitted: boolean;
}) {
  const [notes, setNotes] = useState("");
  const [pending, startTransition] = useTransition();
  const [result, setResult] = useState<ApprovalActionResult | null>(null);

  if (approvalStatus !== "pending") {
    return null;
  }

  if (decisionSubmitted) {
    return (
      <section className="rounded border border-amber-700 bg-amber-950/30 p-4 text-sm text-amber-100">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-amber-200">
          Decision queued
        </h2>
        <p className="mt-1 text-xs text-amber-200/80">
          Worker is resuming the LangGraph thread. Page will reflect the
          final approval status once writeback completes.
        </p>
      </section>
    );
  }

  function submit(decision: "approve" | "reject") {
    startTransition(async () => {
      const fd = new FormData();
      fd.set("notes", notes);
      const res =
        decision === "approve"
          ? await approveInvestigation(investigationId, fd)
          : await rejectInvestigation(investigationId, fd);
      setResult(res);
    });
  }

  return (
    <section className="rounded border border-amber-700 bg-amber-950/40 p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-amber-200">
        Awaiting analyst decision
      </h2>
      <textarea
        className="mt-3 w-full rounded border border-amber-800 bg-zinc-950/60 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-amber-500 focus:outline-none"
        rows={3}
        maxLength={1024}
        placeholder="Optional notes (≤ 1024 chars)…"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        disabled={pending}
      />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={pending}
          onClick={() => submit("approve")}
          className="rounded bg-emerald-700 px-3 py-1.5 text-sm font-medium text-emerald-50 hover:bg-emerald-600 disabled:opacity-50"
        >
          Approve verdict
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => submit("reject")}
          className="rounded bg-red-700 px-3 py-1.5 text-sm font-medium text-red-50 hover:bg-red-600 disabled:opacity-50"
        >
          Reject (skip writeback)
        </button>
        {pending ? (
          <span className="text-xs text-amber-300">submitting…</span>
        ) : null}
      </div>
      {result ? (
        <p
          className={`mt-3 text-xs ${
            result.ok ? "text-emerald-300" : "text-red-300"
          }`}
        >
          {result.ok
            ? "Decision queued — page will refresh."
            : `Failed: ${result.error}${result.detail ? ` · ${result.detail}` : ""}`}
        </p>
      ) : null}
    </section>
  );
}
