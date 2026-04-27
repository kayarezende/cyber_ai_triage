import { severityClasses } from "@/lib/format";

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${severityClasses(value)}`}
    >
      {value ?? "—"}
    </span>
  );
}
