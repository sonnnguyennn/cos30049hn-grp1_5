'use client';

import { usePathname } from "next/navigation";
import Link from "next/link";
import clsx from "clsx";

const links = [
    {Name: 'Dashboard', href: '/dashboard'},
    {Name: 'Dataset Explorer', href: '/dashboard/dataset-explorer'},
    {Name: 'Model Evaluation', href: '/dashboard/model-evaluation'},
    {Name: 'Prediction', href: '/dashboard/prediction'},
    {Name: 'Edge Benchmark', href: '/dashboard/edge-benchmark'},
    {Name: 'Goon Corner', href: '/dashboard/goon'},
]

export default function NavLinks() {
    const pathname = usePathname()
    return (
        <>
            {
                links.map((link) => {
                    return (
                        <Link
                        key={link.Name}
                        href={link.href}
                        className={clsx("flex w-full rounded-2xl",
                            {"flex w-full rounded-2xl bg-[#ddf1ea]" : pathname === link.href}
                        )}
                        >
                            <p className={clsx(
                                "text-[#3d3d3d] text-xl py-2 px-8",
                                {"text-[#05bb7e] text-xl py-2 px-8" : pathname === link.href}
                            )}>{link.Name}</p>
                        </Link>
                    )
                })
            }
        </>
    );
}