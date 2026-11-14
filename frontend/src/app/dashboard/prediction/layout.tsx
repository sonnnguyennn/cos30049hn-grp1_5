"use client";

import { inter } from '@/app/ui/fonts';
import AnalysisSwitch from '@/app/ui/prediction/analysis-switch';

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <h1 className={`${inter.className} text-4xl text-black`}>Prediction</h1>
      <div className='flex w-full h-full items-center gap-3'>
        <div className='flex flex-col w-5 h-5 rounded-full bg-green-500'></div>
        <p className='text-gray-700 text-2xl'>Model service operational</p>
      </div>
      <h2 className={`${inter.className} text-2xl text-gray-500`}>Classify pre-extracted N-BaIoT feature records as benign or malicious.</h2>
      
      <div className="page-break h-3"></div>
      <AnalysisSwitch />
      <div className="page-break h-3"></div>
      
      <div>{children}</div>
    </div>
  );
}