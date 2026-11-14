"use client";
import { inter } from '@/app/ui/fonts';
import InputPrediction from '@/app/ui/prediction/input-prediction';
import ManualResults from '@/app/ui/prediction/manual-results';

export default function Page() {
    return (
        <main className='flex gap-5'>
            <InputPrediction />
            <ManualResults />
        </main>
    );
}

