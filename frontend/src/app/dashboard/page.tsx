"use client";

import { inter } from '@/app/ui/fonts';
import NewAnal from '../ui/dashboard/new-analysis';
import MoreLinks from '../ui/dashboard/more-links';

export default function Page() {
    return (
        <main className='grid gap-y-5'>
            <h1 className={`${inter.className} text-5xl text-black`}>Dashboard</h1>
            <h2 className={`${inter.className} text-2xl text-gray-500`}>Service Status: [Status]</h2>
            <div className="page-break h-5"></div>
            <NewAnal />
            <MoreLinks />
        </main>
    );
}

