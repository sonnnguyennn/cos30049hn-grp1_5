"use client";

import SideNav from "../ui/dashboard/sidenav";
import { inter } from '@/app/ui/fonts';

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen flex-col md:flex-row md:overflow-hidden">
      <SideNav />
      <div className={`${inter.className} antialiased min-w-0 grow p-6 md:overflow-y-auto md:p-12`}>{children}</div>
    </div>
  );
}
