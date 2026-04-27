"use client";

import { useState } from "react";

export function JsonBlock({
  value,
  collapsed = false,
  maxChars = 4000,
}: {
  value: unknown;
  collapsed?: boolean;
  maxChars?: number;
}) {
  const [open, setOpen] = useState(!collapsed);
  const text = JSON.stringify(value, null, 2);
  const isTruncated = text.length > maxChars;
  const display = isTruncated && !open ? text.slice(0, maxChars) : text;

  return (
    <div className="rounded border border-zinc-800 bg-zinc-900/60">
      <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-xs text-zinc-200">
        {display}
        {isTruncated && !open ? "…" : ""}
      </pre>
      {isTruncated ? (
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="block w-full border-t border-zinc-800 bg-zinc-900 py-1 text-center text-xs text-zinc-400 hover:bg-zinc-800"
        >
          {open ? "collapse" : `show full (${text.length} chars)`}
        </button>
      ) : null}
    </div>
  );
}
