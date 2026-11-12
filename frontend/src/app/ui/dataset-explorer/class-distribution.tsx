'use client';

import { Bar, BarChart, LabelList, LabelProps, XAxis, YAxis, Text } from 'recharts';
import { RechartsDevtools } from '@recharts/devtools';

const data = [
    { month: 'Jan', revenue: 4200, profit: 1100 },
    { month: 'Feb', revenue: 5800, profit: 1500 },
    { month: 'Mar', revenue: 7200, profit: 2400 },
    { month: 'Apr', revenue: 6100, profit: 1800 },
    { month: 'May', revenue: 8900, profit: 3100 },
    { month: 'Jun', revenue: 7400, profit: 2600 },
];

function ProfitLabel({ x, y, width, value }: LabelProps) {
  if (x == null || y == null || width == null) {
    return null;
  }

  return (
    <Text x={Number(x) + Number(width) / 2} y={Number(y)} dy={-6} textAnchor="middle" fontSize={11}>
      {`▲ ${value}`}
    </Text>
  );
}

const formatMonth = (value: string): string => value.toUpperCase();

const formatThousands = (value: number): string => `${value / 1000}k`;


export default function ClassDistribution() {
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-auto rounded-4xl px-10 py-10 gap-5 relative'>
            <p className='text-2xl text-black'>Class distribution by device</p>
            <div className='bg-green-100 w-60 h-15 absolute top-10 right-10 rounded-4xl flex p-5 items-center gap-5'>
                <div className='bg-green-400 h-full aspect-square rounded-full'></div>
                <p className='text-xl text-green-500'>Available</p>
            </div>

            <BarChart
                style={{ width: '100%', maxHeight: '25vh', aspectRatio: 1.618 }}
                responsive
                data={data}
                margin={{ top: 25, right: 30, left: 20, bottom: 25 }}
            >
                {/* Axis titles are the `label` prop; tick text goes through `tickFormatter`. */}
                <XAxis
                    dataKey="month"
                    tickFormatter={formatMonth}
                    label={{ position: 'insideBottomRight', value: 'Month', offset: -10 }}
                />
                <YAxis
                    tickFormatter={formatThousands}
                    label={{ position: 'insideTopLeft', value: 'Revenue', angle: -90, dy: 60 }}
                />
                {/* LabelList with a formatter covers the common case ... */}
                <Bar dataKey="revenue">
                    <LabelList dataKey="revenue" position="top" formatter={label => `${Number(label) / 1000}k`} fontSize={11} />
                </Bar>
                {/* ... and a `content` component covers everything else. */}
                <Bar dataKey="profit">
                    <LabelList dataKey="profit" content={ProfitLabel} />
                </Bar>
                <RechartsDevtools />
            </BarChart>
        </div>
    );
}
