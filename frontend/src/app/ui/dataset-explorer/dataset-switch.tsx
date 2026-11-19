'use client';

import clsx from 'clsx';

type DatasetSwitchProps = {
    currentDataset: number;
    setDataset: (dataset: number) => void;
};

export default function DatasetSwitch({ currentDataset, setDataset }: DatasetSwitchProps) {
    return (
        <div className='flex h-12 w-full max-w-100 shrink-0 rounded-4xl bg-[#FFFFFF] p-2 @min-[64rem]:w-100 @min-[64rem]:h-15'>
            <button type='button' onClick={() => setDataset(1)}
                className={
                clsx("h-full min-w-0 flex-1 cursor-pointer rounded-4xl hover:bg-[#BFE5D7]",
                    {"bg-[#ddf1ea]" : currentDataset === 1}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xs lg:text-base",
                    {"text-[#127A63] text-xs lg:text-base" : currentDataset === 1}
                )}>N-BaIoT (Primary)</p>
            </button>

            <button type='button' onClick={() => setDataset(2)}
                className={
                clsx("h-full min-w-0 flex-1 cursor-pointer rounded-4xl hover:bg-[#BFE5D7]",
                    {"bg-[#ddf1ea]" : currentDataset === 2}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xs lg:text-base",
                    {"text-[#127A63] text-xs lg:text-base" : currentDataset === 2}
                )}>Bot-IoT (Secondary)</p>
            </button>
        </div>
    );
}
