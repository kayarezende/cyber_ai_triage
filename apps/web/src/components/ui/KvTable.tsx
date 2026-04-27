interface KvRow {
  key: string;
  value: React.ReactNode;
}

export function KvTable({ rows }: { rows: KvRow[] }) {
  return (
    <table className="w-full border-collapse text-sm">
      <tbody>
        {rows.map((row) => (
          <tr key={row.key} className="border-b border-zinc-800 last:border-b-0">
            <th className="w-1/3 py-1.5 pr-4 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">
              {row.key}
            </th>
            <td className="py-1.5 text-zinc-200">{row.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
