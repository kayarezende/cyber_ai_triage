// Display helpers shared by server + client components.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

const SEVERITY_BG: Record<Severity, string> = {
  info: "bg-zinc-700 text-zinc-100",
  low: "bg-emerald-700 text-emerald-50",
  medium: "bg-amber-600 text-amber-50",
  high: "bg-orange-600 text-orange-50",
  critical: "bg-red-700 text-red-50",
};

export function severityClasses(value: string | null | undefined): string {
  if (!value) return "bg-zinc-800 text-zinc-300";
  const key = value.toLowerCase() as Severity;
  return SEVERITY_BG[key] ?? "bg-zinc-800 text-zinc-300";
}

export function formatTs(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return value;
    return dt.toISOString().replace("T", " ").replace("Z", "Z");
  } catch {
    return value;
  }
}

export function formatUsd(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `$${value.toFixed(4)}`;
}

export function truncate(value: string | null | undefined, max: number): string {
  if (!value) return "";
  if (value.length <= max) return value;
  return value.slice(0, max - 1) + "…";
}
