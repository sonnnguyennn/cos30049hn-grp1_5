'use client';

import { inter } from '@/app/ui/fonts';
import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';

export default function NewAnal() {
    return (
        <div className='flex items-center bg-[#ddf1ea] w-full h-80 rounded-4xl px-15 py-15 gap-150'>
            <div className = 'flex flex-col justify-center gap-y-3'>
                <h1 className={`${inter.className} text-4xl text-black`}>New analysis</h1>
                <h1 className={`${inter.className} text-xl text-gray-400`}>Run a prediction on a sample, CSV file or JSON record.</h1>
                <div className="page-break"></div>

                <Link href='/dashboard/prediction' className='flex justify-center items-center rounded-4xl w-45 h-15 text-xl text-white bg-black'>
                    Start analysis
                </Link>
            </div>
            <div className='bg-[#BFE5D7] rounded-full w-60 h-60 flex justify-center items-center'>
                <ShieldCheck fill='white' size={150} nonScalingStroke stroke='#127A63' strokeWidth={10} className=''/>
            </div>
        </div>
    );
}


