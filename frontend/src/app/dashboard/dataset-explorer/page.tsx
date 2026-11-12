"use client";

import { inter } from '@/app/ui/fonts';
import DatasetSwitch from '@/app/ui/dataset-explorer/dataset-switch';
import { useState } from 'react';
import RecordsFeaturesClasses from '@/app/ui/dataset-explorer/records-features-classes';
import ClassDistribution from '@/app/ui/dataset-explorer/class-distribution';

const datasetSummaries = [
  // Dataset 1 — N-BaIoT (Primary)
  [
    { label: 'Records', value: 7_062_606 },
    { label: 'Features', value: 115 },
    { label: 'Classes', value: 2, detail: 'Benign, Malicious' },
    { label: 'Train records', value: 4_944_968 },
    { label: 'Validation records', value: 1_056_372 },
    { label: 'Test records', value: 1_061_266 },
    { label: 'Benign records', value: null },
    { label: 'Malicious records', value: null },
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
        <main className='grid gap-y-5 relative'>
            <h1 className={`${inter.className} text-5xl text-black`}>Dataset explorer</h1>
            <h2 className={`${inter.className} text-2xl text-gray-500`}>Summaries of the processed dataset. Raw records are not displayed.</h2>
            <div className="page-break h-5"></div>

            <DatasetSwitch currentDataset={currentDataset} setDataset={setDataset} />
            <RecordsFeaturesClasses currentDataset={currentDataset} data={datasetSummaries} />
            <ClassDistribution />
        </main>
    );
}

