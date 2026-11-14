'use client';

import clsx from 'clsx';
import { usePathname } from "next/navigation";

type DatasetSwitchProps = {
    currentDataset: number;
    setDataset: (dataset: number) => void;
};

export default function DatasetSwitch({ currentDataset, setDataset }: DatasetSwitchProps) {
    return (
        <div className='flex w-70 h-10 lg:w-100 lg:h-15 bg-[#FFFFFF] rounded-4xl absolute right-0 p-2'>
            <button type='button' onClick={() => setDataset(1)}
                className={
                clsx("rounded-4xl h-full w-50", 
                    {"rounded-4xl h-full w-50 bg-[#ddf1ea]" : currentDataset === 1}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xs lg:text-base",
                    {"text-[#127A63] text-xs lg:text-base" : currentDataset === 1}
                )}>N-BaIoT (Primary)</p>
            </button>

            <button type='button' onClick={() => setDataset(2)}
                className={
                clsx("rounded-4xl h-full w-50", 
                    {"rounded-4xl h-full w-50 bg-[#ddf1ea]" : currentDataset === 2}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xs lg:text-base",
                    {"text-[#127A63] text-xs lg:text-base" : currentDataset === 2}
                )}>Bot-IoT (Secondary)</p>
            </button>
        </div>
    );
}
