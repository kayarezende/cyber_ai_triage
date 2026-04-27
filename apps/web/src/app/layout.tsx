import type { Metadata } from "next";
import "./globals.css";

import { TopBar } from "@/components/nav/TopBar";

export const metadata: Metadata = {
  title: "Sentient Layer",
  description: "AI SOC triage console",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-zinc-950 text-zinc-100 antialiased">
        <TopBar />
        <main className="mx-auto w-full max-w-7xl px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
