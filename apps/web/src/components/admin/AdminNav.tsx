"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const ITEMS = [
  { href: "/admin/llm-roles", label: "LLM roles" },
  { href: "/admin/hitl-policies", label: "HITL policies" },
  { href: "/admin/budgets", label: "Budgets" },
  { href: "/admin/splunk", label: "Splunk" },
  { href: "/admin/users", label: "Users" },
  { href: "/admin/usage", label: "Usage" },
];

export function AdminNav() {
  const pathname = usePathname();
  return (
    <nav className="flex flex-col gap-1 text-sm">
      {ITEMS.map((item) => {
        const active = pathname.startsWith(item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            className={
              active
                ? "rounded bg-zinc-800 px-3 py-2 text-zinc-100"
                : "rounded px-3 py-2 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
            }
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
