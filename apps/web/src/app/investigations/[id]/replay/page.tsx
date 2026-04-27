import Link from "next/link";
import { notFound } from "next/navigation";

import { CheckpointStepper } from "@/components/replay/CheckpointStepper";
import { StateDiff } from "@/components/replay/StateDiff";
import { JsonBlock } from "@/components/ui/JsonBlock";
import { ApiError, NotFoundError, apiFetch } from "@/lib/api";
import type {
  CheckpointDetail,
  CheckpointList,
  CheckpointSummary,
} from "@/lib/types";

interface PageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ cp?: string }>;
}

export const dynamic = "force-dynamic";

export default async function ReplayPage({ params, searchParams }: PageProps) {
  const { id } = await params;
  const { cp } = await searchParams;

  let listing: CheckpointList;
  try {
    listing = await apiFetch<CheckpointList>(
      `/api/replay/${id}/checkpoints`,
      { searchParams: { limit: 200 } },
    );
  } catch (err) {
    if (err instanceof NotFoundError) {
      notFound();
    }
    if (err instanceof ApiError && err.status === 503) {
      return (
        <div className="rounded border border-amber-800 bg-amber-950/40 p-3 text-sm text-amber-100">
          Replay is unavailable: API checkpointer pool failed to open. Verify
          DATABASE_URL on the api container.
        </div>
      );
    }
    if (err instanceof ApiError) {
      return (
        <div className="rounded border border-red-800 bg-red-950 p-3 text-sm text-red-200">
          API error {err.status}: {err.path}
        </div>
      );
    }
    throw err;
  }

  const items: CheckpointSummary[] = listing.items;
  const activeId = cp ?? items[0]?.checkpoint_id ?? null;

  let detail: CheckpointDetail | null = null;
  let parent: CheckpointDetail | null = null;
  if (activeId) {
    try {
      detail = await apiFetch<CheckpointDetail>(
        `/api/replay/${id}/checkpoints/${activeId}`,
      );
    } catch (err) {
      if (!(err instanceof NotFoundError)) throw err;
    }
    if (detail?.parent_checkpoint_id) {
      try {
        parent = await apiFetch<CheckpointDetail>(
          `/api/replay/${id}/checkpoints/${detail.parent_checkpoint_id}`,
        );
      } catch (err) {
        if (!(err instanceof NotFoundError)) throw err;
      }
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link
          href={`/investigations/${id}`}
          className="text-xs text-zinc-500 hover:text-zinc-300"
        >
          ← back to investigation
        </Link>
        <h1 className="mt-1 text-lg font-semibold text-zinc-100">
          Time-travel replay
        </h1>
        <p className="text-xs text-zinc-500">
          {items.length} checkpoint{items.length === 1 ? "" : "s"} from
          LangGraph state
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
        <CheckpointStepper
          investigationId={id}
          items={items}
          activeId={activeId}
        />
        <div className="flex flex-col gap-3">
          {detail ? (
            <>
              <section className="rounded border border-zinc-800 bg-zinc-900 p-3">
                <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-400">
                  Metadata · checkpoint{" "}
                  <span className="font-mono">{detail.checkpoint_id}</span>
                </h2>
                <JsonBlock value={detail.metadata} collapsed maxChars={1500} />
              </section>
              <section className="rounded border border-zinc-800 bg-zinc-900 p-3">
                <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-400">
                  State diff vs parent
                </h2>
                <StateDiff
                  before={parent?.channel_values ?? null}
                  after={detail.channel_values}
                />
              </section>
            </>
          ) : (
            <div className="rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-zinc-500">
              {activeId
                ? "Checkpoint not found."
                : "Select a checkpoint to view state."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
