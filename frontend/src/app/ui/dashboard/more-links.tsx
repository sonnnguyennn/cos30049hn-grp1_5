'use client';

import Link from "next/link";
import { ArrowRight } from 'lucide-react';

const links = [
    {Name: 'Dataset Explorer', href: '/dashboard/dataset-explorer', color: 'bg-[#E1ECF8]', des: 'N-BaIot primary dataset'},
    {Name: 'Model Evaluation', href: '/dashboard/model-evaluation', color: 'bg-[#F6EEDF]', des: '3 candidate models'},
    {Name: 'Edge Benchmark', href: '/dashboard/edge-benchmark', color: 'bg-[#FFFFFF]', des: 'Raspberry Pi 4'},
]

export default function MoreLinks() {
    return (
        <div className='flex items-center justify-center w-full h-40 rounded-2xl gap-10'>
            {
                links.map((link) => {
                    return(
                        <Link
                        key={link.Name}
                        href={link.href}
                        className={`relative w-full h-full rounded-4xl justify-center flex flex-col px-10 ${link.color}`}
                        >
                            <p className="text-black text-2xl">{link.Name}</p>
                            <p className="text-gray-400">{link.des}</p>
                            <ArrowRight stroke="gray" size={30} className="absolute top-5 right-5" />
                        </Link>
                    )
                })
            }
        </div>
    );
}

