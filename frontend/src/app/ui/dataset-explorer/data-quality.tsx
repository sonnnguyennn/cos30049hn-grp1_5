'use client';

import clsx from 'clsx';

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
        <div className='flex min-w-0 flex-col bg-[#FFFFFF] w-full h-auto rounded-4xl p-5 sm:p-8 gap-5'>
            <p className='text-2xl text-black'>Data Quality</p>
            <div className='grid min-w-0 grid-cols-1 gap-5 @min-[40rem]:grid-cols-2 @min-[64rem]:grid-cols-4'>
                {
                    data[currentDataset-1].map(({label, description, status}) => {
                        return (
                            <div key={label} className='flex min-w-0 flex-col gap-5'>
                                <div className='flex items-center gap-3'>
                                    <div className={clsx('flex shrink-0 flex-col w-5 h-5 rounded-full',
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


