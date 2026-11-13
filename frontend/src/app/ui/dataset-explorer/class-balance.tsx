'use client';

import { PieChart, Pie, Sector, PieSectorShapeProps, Label, LabelList, LabelProps } from 'recharts';
import { RechartsDevtools } from '@recharts/devtools';

type SummaryField = {
  label: string;
  value: number | null;
};

type Props = {
  currentDataset: number;
  data: SummaryField[][];
};

const colors = ['#127A63', '#9dccbb'];

const MyCustomPie = (props: PieSectorShapeProps) => <Sector {...props} fill={colors[props.index % colors.length]} />;

const MyCustomLabel = (props: LabelProps) => (
  <Label {...props} fill={colors[(props.index ?? 0) % colors.length]} position="outside" offset={20} />
);

export default function ClassBalance({ currentDataset, data }: Props) {
    const selectedDataset = data[currentDataset - 1] ?? [];
    const pieData = ['Benign', 'Malicious'].map(name => ({
        name,
        value: selectedDataset.find(field => field.label === `${name} records`)?.value ?? 0,
    }));

    const total = pieData.reduce((sum, entry) => sum + entry.value, 0);
    const formatPercentage = (value: number) =>
        total > 0
            ? `${Number(((value / total) * 100).toFixed(1))}%`
            : 'N/A';

    return (
        <div className='flex flex-col bg-[#ddf1ea] w-full h-auto rounded-4xl px-10 py-10 gap-10 relative basis-1/2'>
            <p className='text-2xl text-black'>Class balance</p>
            <PieChart style={{ width: '100%', height: 240, flexShrink: 1 }} responsive>
                <Pie data={pieData} dataKey="value" innerRadius={70} outerRadius={100} isAnimationActive={true} shape={MyCustomPie}>
                    <LabelList content={MyCustomLabel} />
                </Pie>
                <RechartsDevtools />
            </PieChart>

            <div className='flex gap-10'>
                {pieData.map(entry => (
                    <p key={entry.name} className='text-gray-500'>
                        {formatPercentage(entry.value)} {entry.name.toLowerCase()}
                    </p>
                ))}
            </div>
        </div>
    );
}
