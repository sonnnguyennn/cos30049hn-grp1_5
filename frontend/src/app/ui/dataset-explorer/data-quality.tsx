'use client';

import clsx from 'clsx';
import Link from 'next/link';

const data = [
    [
      {
        label: 'Package verification',
        description: 'Payload checks passed. Team verification is pending.',
        status: 'caution',
      },
      {
        label: 'Split protocol',
        description: 'The package reuses the canonical train, validation, and test splits.',
        status: 'verified',
      },
      {
        label: 'Duplicate handling',
        description: 'The package retains all rows. No deduplication was applied.',
        status: 'caution',
      },
      {
        label: 'Scaling',
        description: 'The scaler was fitted on training records only.',
        status: 'verified',
      },
    ],
    [
      {
        label: 'Package verification',
        description: 'Verification results pending.',
        status: 'pending',
      },
      {
        label: 'Split protocol',
        description: 'Split sizes shown are for the UI demo.',
        status: 'pending',
      },
      {
        label: 'Duplicate handling',
        description: 'Duplicate checks pending.',
        status: 'pending',
      },
      {
        label: 'Scaling',
        description: 'Preprocessing details pending.',
        status: 'pending',
      },
    ],
]

type Props = {
    currentDataset: number;
};

export default function DataQuality({currentDataset} : Props) {
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-auto rounded-4xl px-10 py-10 gap-5'>
            <p className='text-2xl text-black'>Data Quality</p>
            <div className='w-full h-auto p-5 flex justify-evenly gap-5'>
                {
                    data[currentDataset-1].map(({label, description, status}) => {
                        return (
                            <div className='flex flex-col w-full h-full gap-5'>
                                <div className='flex w-full h-full items-center gap-5'>
                                    <div className={clsx('flex flex-col w-5 h-5 rounded-full',
                                        {'flex flex-col w-5 h-5 bg-amber-300 rounded-full': status === "pending"},
                                        {'flex flex-col w-5 h-5 bg-amber-300 rounded-full': status === "caution"},
                                        {'flex flex-col w-5 h-5 bg-green-500 rounded-full': status === "verified"}
                                    )}
                                    ></div>
                                    <p className='text-black'>{label}</p>
                                </div>
                                
                                <p className='text-gray-400'>{description}</p>
                            </div>
                        );
                    })
                }
            </div>
        </div>
    );
}


