'use client';

import { useState } from 'react';
import { Bar, BarChart, LabelList, ResponsiveContainer, XAxis, YAxis, Tooltip } from 'recharts';

const data = [
    [
        { device: "Danmini Doorbell", benign: 49548, malicious: 968750 },
        { device: "Ecobee Thermostat", benign: 13113, malicious: 822763 },
        { device: "Ennio Doorbell", benign: 39100, malicious: 316400 },
        { device: "Philips Baby Monitor", benign: 175240, malicious: 923437 },
        { device: "Provision PT-737E", benign: 62154, malicious: 766106 },
        { device: "Provision PT-838", benign: 98514, malicious: 738377 },
        { device: "Samsung Webcam", benign: 52150, malicious: 323072 },
        { device: "SimpleHome XCS7-1002", benign: 46585, malicious: 816471 },
        { device: "SimpleHome XCS7-1003", benign: 19528, malicious: 831298 },
    ],
    [
        { device: "D1", benign: 12000, malicious: 68000 },
        { device: "D2", benign: 8000, malicious: 52000 },
        { device: "D3", benign: 15000, malicious: 75000 },
        { device: "D4", benign: 6000, malicious: 44000 },
        { device: "D5", benign: 9000, malicious: 61000 },
        { device: "D6", benign: 14000, malicious: 86000 },
        { device: "D7", benign: 11000, malicious: 39000 },
    ]
    ];


type Props = {
    currentDataset: number;
};

export default function ClassDistribution({ currentDataset }: Props) {
    const [isCompact, setIsCompact] = useState(true);

    return (
        <div className='flex min-w-0 flex-col bg-[#FFFFFF] rounded-4xl p-5 sm:p-8 gap-5'>
            <div className='flex flex-wrap items-start justify-between gap-3'>
                <p className='text-2xl text-black'>Class distribution by device</p>
                <div className='bg-[#DDF1EA] h-10 shrink-0 rounded-4xl flex p-3 items-center gap-3'>
                    <div className='bg-[#127A63] h-3 w-3 rounded-full'></div>
                    <p className='text-[#127A63]'>Available</p>
                </div>
            </div>

            <div className='h-90 w-full min-w-0'>
                <ResponsiveContainer width="100%" height="100%" minWidth={0} onResize={(width) => setIsCompact(width < 560)}>
                    <BarChart
                        data={data[currentDataset-1]}
                        layout={isCompact ? 'vertical' : 'horizontal'}
                        margin={isCompact
                            ? { top: 8, right: 8, left: 0, bottom: 8 }
                            : { top: 25, right: 8, left: 30, bottom: 8 }}
                    >
                        {/* Horizontal bars leave room for device names in narrow cards. */}
                        {isCompact ? (
                            <>
                                <XAxis type="number" hide />
                                <YAxis
                                    type="category"
                                    dataKey="device"
                                    width={110}
                                    interval={0}
                                    tick={{ width: 100, fontSize: 11 }}
                                    axisLine={false}
                                    tickLine={false}
                                />
                            </>
                        ) : <XAxis
                            dataKey="device"
                            interval={0}
                            height={90}
                            angle={-45}
                            textAnchor="end"
                            tick={{ width: 70, fontSize: 11 }}
                            axisLine={false}
                            tickLine={false}
                        />}
                        <Tooltip
                            cursor={{ fill: '#F0F8F4' }}
                            contentStyle={{
                                backgroundColor: '#FFFFFF',
                                border: '2px solid #BFE5D7',
                                borderRadius: 12,
                                padding: '12px 16px',
                            }}
                            labelStyle={{ color: '#164B3E', fontWeight: 600, marginBottom: 6 }}
                            itemStyle={{ color: '#127A63' }}
                            formatter={(value, name) => [
                                Number(value).toLocaleString('en-US'),
                                name === 'benign' ? 'Benign' : 'Malicious',
                            ]}
                        />
                        <Bar dataKey="benign" stackId="classes" fill='#BFE5D7' maxBarSize={40} radius={isCompact ? [5, 0, 0, 5] : [0, 0, 5, 5]}>
                            {!isCompact && <LabelList dataKey="benign" position="bottom" fontSize={10} offset={-10} fill='#127A63' />}
                        </Bar>
                        <Bar dataKey="malicious" stackId="classes" fill='#E9EEED' maxBarSize={40} radius={isCompact ? [0, 5, 5, 0] : [5, 5, 0, 0]}>
                            {!isCompact && <LabelList dataKey="malicious" fontSize={10} position="top" offset={-10} />}
                        </Bar>
                    </BarChart>
                </ResponsiveContainer>
            </div>

            <div className='mt-auto flex flex-wrap gap-x-6 gap-y-2'>
                <div className='flex items-center gap-3'>
                    <div className='bg-[#BFE5D7] w-5 h-5 shrink-0 rounded-full'></div>
                    <p className='text-gray-500'>Benign</p>
                </div>
                <div className='flex items-center gap-3'>
                    <div className='bg-[#E9EEED] w-5 h-5 shrink-0 rounded-full'></div>
                    <p className='text-gray-500'>Malicious</p>
                </div>
            </div>
        </div>
    );
}
