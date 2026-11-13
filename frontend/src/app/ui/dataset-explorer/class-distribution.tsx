'use client';

import { Bar, BarChart, LabelList, XAxis, Tooltip } from 'recharts';
import { RechartsDevtools } from '@recharts/devtools';

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
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-auto rounded-4xl px-10 py-10 gap-5 relative'>
            <p className='text-2xl text-black'>Class distribution by device</p>
            <div className='bg-[#DDF1EA] w-auto h-10 absolute top-5 right-5 rounded-4xl flex p-3 items-center gap-3'>
                <div className='bg-[#127A63] h-full aspect-square rounded-full'></div>
                <p className='text-[#127A63]'>Available</p>
            </div>

            <BarChart
                style={{ width: '100%', maxHeight: '30vh', aspectRatio: 1.618 }}
                responsive
                data={data[currentDataset-1]}
                margin={{ top: 25, right: 30, left: 20, bottom: 25 }}
            >
                {/* Axis titles are the `label` prop; tick text goes through `tickFormatter`. */}

                <XAxis
                    dataKey="device"
                    interval={0}
                    tick={{ width: 100, maxLines: 1, fontSize: 14 }}
                    axisLine={false}
                    tickLine={false}
                />
                <Tooltip
                    defaultIndex={2}
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
                {/* LabelList with a formatter covers the common case ... */}
                <Bar dataKey="benign" stackId="goon" fill='#BFE5D7' barSize={40} radius={[0, 0, 5, 5]}>
                    <LabelList dataKey="benign" position="bottom" fontSize={11} offset={-10} fill='#127A63' />
                </Bar>
                {/* ... and a `content` component covers everything else. */}
                <Bar dataKey="malicious" stackId="goon" fill='#E9EEED' radius={[5, 5, 0, 0]}>
                    <LabelList dataKey="malicious" fontSize={11} position="top" offset={-10} />
                </Bar>
                <RechartsDevtools />
            </BarChart>

            <div className='flex gap-3 items-center'>
                <div className='bg-[#BFE5D7] w-5 h-5 rounded-full'></div>
                <p className='text-gray-500'>Benign</p>
                <div className='w-5'></div>
                <div className='bg-[#E9EEED] w-5 h-5 rounded-full'></div>
                <p className='text-gray-500'>Malicious</p>
            </div>
        </div>
    );
}
