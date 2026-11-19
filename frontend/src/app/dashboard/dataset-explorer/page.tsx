"use client";

import { inter } from '@/app/ui/fonts';
import DatasetSwitch from '@/app/ui/dataset-explorer/dataset-switch';
import { useState } from 'react';
import RecordsFeaturesClasses from '@/app/ui/dataset-explorer/records-features-classes';
import ClassDistribution from '@/app/ui/dataset-explorer/class-distribution';
import ClassBalance from '@/app/ui/dataset-explorer/class-balance';
import DataQuality from '@/app/ui/dataset-explorer/data-quality';

const datasetSummaries = [
  // Dataset 1 — N-BaIoT (Primary)
  [
    { label: 'Records', value: 7_062_606 },
    { label: 'Features', value: 115 },
    { label: 'Classes', value: 2, detail: 'Benign, Malicious' },
    { label: 'Train records', value: 4_944_968 },
    { label: 'Validation records', value: 1_056_372 },
    { label: 'Test records', value: 1_061_266 },
    { label: 'Benign records', value: 6700 },
    { label: 'Malicious records', value: 3300 },
  ],

  // Dataset 2 — Bot-IoT (Secondary, mock data)
  [
    { label: 'Records', value: 24_000 },
    { label: 'Features', value: 32 },
    { label: 'Classes', value: 2, detail: 'Benign, Malicious' },
    { label: 'Train records', value: 16_800 },
    { label: 'Validation records', value: 3_600 },
    { label: 'Test records', value: 3_600 },
    { label: 'Benign records', value: 6_000 },
    { label: 'Malicious records', value: 18_000 },
  ],
];


export default function Page() {
    const [currentDataset, setDataset] = useState(1);

    return (
        <main className='@container grid min-w-0 grid-cols-1 gap-y-2'>
            <div className='flex min-w-0 flex-col gap-4 @min-[64rem]:flex-row @min-[64rem]:items-start @min-[64rem]:justify-between'>
              <div className='min-w-0'>
                <h1 className={`${inter.className} text-4xl text-black`}>Dataset explorer</h1>
                <h2 className={`${inter.className} text-2xl text-gray-500`}>Summaries of the processed dataset. Raw records are not displayed.</h2>
              </div>
              <DatasetSwitch currentDataset={currentDataset} setDataset={setDataset} />
            </div>
            <div className="page-break h-3"></div>

            <RecordsFeaturesClasses currentDataset={currentDataset} data={datasetSummaries} />

            <div className="page-break h-1"></div>
            <div className='grid min-w-0 grid-cols-1 gap-5 @min-[64rem]:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]'>
              <ClassDistribution currentDataset={currentDataset} />
              <ClassBalance currentDataset={currentDataset} data={datasetSummaries} />
            </div>

            <div className="page-break h-1"></div>
            <DataQuality currentDataset={currentDataset}/>
            
        </main>
    );
}

