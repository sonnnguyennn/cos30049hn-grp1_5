'use client';

import Link from 'next/link';

export default function InputPrediction() {
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-full rounded-4xl px-10 py-10 gap-5'>
            <p className='text-2xl text-black'>Input</p>
            <p className='text-xl text-gray-400'>Choose a sample, upload a CSV file or paste a JSON record.</p>
        </div>
    );
}


