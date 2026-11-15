"use client";
import InputPrediction from '@/app/ui/prediction/input-prediction';
import ManualResults from '@/app/ui/prediction/manual-results';
import type { Analysis } from '@/app/ui/prediction/types';
import { useState } from 'react';

export default function Page() {
    const [result, setResult] = useState<Analysis | null>(null);
    const [error, setError] = useState("");

    return (
        <main className='flex flex-col gap-5 xl:flex-row'>
            <InputPrediction error={error} setResult={setResult} setError={setError} />
            <ManualResults result={result} />
        </main>
    );
}

