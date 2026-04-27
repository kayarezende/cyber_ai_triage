import Link from "next/link";

import { currentUser } from "@/lib/auth";

export async function TopBar() {
  const user = await currentUser();
  return (
    <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-3 text-sm">
        <div className="flex items-center gap-6">
          <Link
            href="/investigations"
            className="font-semibold tracking-tight text-zinc-100"
          >
            sentient layer
          </Link>
          <nav className="flex items-center gap-4 text-zinc-400">
            <Link href="/investigations" className="hover:text-zinc-100">
              Investigations
            </Link>
            <Link href="/audit" className="hover:text-zinc-100">
              Audit
            </Link>
          </nav>
        </div>
        <div className="text-xs text-zinc-500 font-mono">
          dev · {user.email} · tenant {user.tenantId.slice(0, 8)}
        </div>
      </div>
    </header>
  );
}
