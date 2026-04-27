"use client";

import { useMemo, useState } from "react";

import { JsonBlock } from "@/components/ui/JsonBlock";

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

interface DiffEntry {
  path: string;
  kind: "added" | "removed" | "changed" | "same";
  before?: unknown;
  after?: unknown;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function diffValues(
  before: unknown,
  after: unknown,
  path = "$",
  acc: DiffEntry[] = [],
): DiffEntry[] {
  if (Object.is(before, after)) {
    return acc;
  }
  if (
    typeof before !== typeof after ||
    Array.isArray(before) !== Array.isArray(after) ||
    (before === null) !== (after === null)
  ) {
    acc.push({ path, kind: "changed", before, after });
    return acc;
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    const max = Math.max(before.length, after.length);
    for (let i = 0; i < max; i++) {
      if (i >= before.length) {
        acc.push({ path: `${path}[${i}]`, kind: "added", after: after[i] });
      } else if (i >= after.length) {
        acc.push({ path: `${path}[${i}]`, kind: "removed", before: before[i] });
      } else {
        diffValues(before[i], after[i], `${path}[${i}]`, acc);
      }
    }
    return acc;
  }
  if (isObject(before) && isObject(after)) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const k of keys) {
      const subPath = `${path}.${k}`;
      if (!(k in before)) {
        acc.push({ path: subPath, kind: "added", after: after[k] });
      } else if (!(k in after)) {
        acc.push({ path: subPath, kind: "removed", before: before[k] });
      } else {
        diffValues(before[k], after[k], subPath, acc);
      }
    }
    return acc;
  }
  if (before !== after) {
    acc.push({ path, kind: "changed", before, after });
  }
  return acc;
}

export function StateDiff({
  before,
  after,
}: {
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const entries = useMemo(
    () => diffValues((before ?? {}) as JsonValue, (after ?? {}) as JsonValue),
    [before, after],
  );

  if (entries.length === 0) {
    return (
      <p className="text-xs text-zinc-500">
        No differences vs parent checkpoint.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-400">
          {entries.length} change{entries.length === 1 ? "" : "s"}
        </span>
        <button
          type="button"
          onClick={() => setShowRaw((v) => !v)}
          className="text-xs text-zinc-400 underline-offset-2 hover:underline"
        >
          {showRaw ? "show diff" : "show raw state"}
        </button>
      </div>
      {showRaw ? (
        <JsonBlock value={after ?? {}} collapsed maxChars={5000} />
      ) : (
        <ul className="space-y-1 text-xs">
          {entries.map((entry, idx) => (
            <li key={idx} className="rounded border border-zinc-800 px-2 py-1">
              <div className="font-mono text-zinc-300">{entry.path}</div>
              {entry.kind === "added" ? (
                <div className="text-emerald-300">
                  + {short(entry.after)}
                </div>
              ) : null}
              {entry.kind === "removed" ? (
                <div className="text-red-300">- {short(entry.before)}</div>
              ) : null}
              {entry.kind === "changed" ? (
                <>
                  <div className="text-red-300">- {short(entry.before)}</div>
                  <div className="text-emerald-300">+ {short(entry.after)}</div>
                </>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function short(v: unknown): string {
  if (v === undefined) return "undefined";
  try {
    const s = JSON.stringify(v);
    return s.length > 200 ? s.slice(0, 200) + "…" : s;
  } catch {
    return String(v);
  }
}
