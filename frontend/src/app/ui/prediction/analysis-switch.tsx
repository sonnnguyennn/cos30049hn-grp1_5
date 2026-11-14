"use client";

import clsx from 'clsx';
import { usePathname } from "next/navigation";
import Link from "next/link";

type DatasetSwitchProps = {
    currentDataset: number;
    setDataset: (dataset: number) => void;
};

export default function AnalysisSwitch() {
    const pathname = usePathname()
    return (
        <div className='flex w-100 h-15 bg-[#FFFFFF] rounded-4xl p-2'>
            <Link href = "/dashboard/prediction/manual-analysis"
                className={
                clsx("rounded-4xl h-full w-50 flex justify-center items-center", 
                    {"rounded-4xl h-full w-50 bg-[#ddf1ea]" : pathname === "/dashboard/prediction/manual-analysis"}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xl",
                    {"text-[#127A63]" : pathname === "/dashboard/prediction/manual-analysis"}
                )}>Manual analysis</p>
            </Link>

            <Link href = "/dashboard/prediction/replay-monitoring"
                className={
                clsx("rounded-4xl h-full w-50 flex justify-center items-center", 
                    {"rounded-4xl h-full w-50 bg-[#ddf1ea]" : pathname === "/dashboard/prediction/replay-monitoring"}
                )}>
                <p className={clsx(
                    "text-[#3d3d3d] text-xl",
                    {"text-[#127A63]" : pathname === "/dashboard/prediction/replay-monitoring"}
                )}>Replay monitoring</p>
            </Link>
        </div>
    );
}
