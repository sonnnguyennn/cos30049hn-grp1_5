"use client";

import SideNav from "../ui/dashboard/sidenav";
import { inter } from '@/app/ui/fonts';

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen flex-col md:flex-row md:overflow-hidden">
      <div className="w-full flex-none md:flex md:w-64 md:flex-col">
        <SideNav />
      </div>
      <div className={`${inter.className} antialiased grow p-6 md:overflow-y-auto md:p-12`}>{children}</div>
    </div>
  );
}