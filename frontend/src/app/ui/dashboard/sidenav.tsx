"use client";

import { useState } from "react";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import { Menu, X } from "lucide-react";
import Link from "next/link";
import Logo from "../logo";
import NavLinks from "./nav-links";

export default function SideNav() {
  const [open, setOpen] = useState(false);
  const content = (
    <nav aria-label="Main navigation" className="flex flex-col py-1">
      <Link className="flex h-25 items-center justify-center" href="/dashboard" onClick={() => setOpen(false)}>
        <Logo />
      </Link>
      <div className="flex flex-col gap-2 px-2" onClick={(event) => {
        if ((event.target as HTMLElement).closest("a")) setOpen(false);
      }}>
        <NavLinks />
      </div>
    </nav>
  );

  return (
    <>
      <div className="flex items-center px-4 pt-4 md:hidden">
        <IconButton aria-label="Open navigation" aria-expanded={open} aria-controls={open ? "mobile-navigation" : undefined} onClick={() => setOpen(true)}>
          <Menu />
        </IconButton>
      </div>
      <Drawer
        variant="temporary"
        open={open}
        onClose={() => setOpen(false)}
        sx={{ "@media (min-width: 768px)": { display: "none" } }}
        slotProps={{ paper: { id: "mobile-navigation", sx: { width: 256 } } }}
      >
        <div className="flex justify-end px-2 pt-2">
          <IconButton aria-label="Close navigation" onClick={() => setOpen(false)}><X /></IconButton>
        </div>
        {content}
      </Drawer>
      <Drawer
        variant="permanent"
        sx={{
          display: "none",
          "@media (min-width: 768px)": { display: "block", width: 256, flexShrink: 0 },
        }}
        slotProps={{ paper: { sx: { width: 224, margin: 2, height: "calc(100% - 32px)", border: 0, borderRadius: 4 } } }}
      >
        {content}
      </Drawer>
    </>
  );
}
