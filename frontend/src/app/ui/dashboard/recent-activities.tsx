'use client';

import Link from 'next/link';

export default function RecentActivities() {
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-auto rounded-4xl px-10 py-10 gap-5'>
            <p className='text-2xl text-black'>Recent activities</p>
            <div className='w-full h-auto bg-[#F2F5F4] rounded-2xl p-5'>
                <p className='text-2xl text-gray-400'>No analysises yet.</p>
            </div>
        </div>
    );
}


