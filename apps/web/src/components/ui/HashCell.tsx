export function HashCell({ value }: { value: string | null | undefined }) {
  if (!value) {
    return <span className="text-zinc-500">—</span>;
  }
  return (
    <span
      title={value}
      className="font-mono text-xs text-zinc-300"
    >
      {value.slice(0, 12)}…
    </span>
  );
}
