import type { ReactNode } from "react";

import { AdminNav } from "@/components/admin/AdminNav";

export default function AdminLayout({ children }: { children: ReactNode }) {
  return (
    <div className="grid grid-cols-[180px_1fr] gap-6">
      <aside className="border-r border-zinc-800 pr-4">
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">
          Admin
        </h2>
        <AdminNav />
      </aside>
      <section>{children}</section>
    </div>
  );
}
