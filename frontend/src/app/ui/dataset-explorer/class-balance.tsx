'use client';

import { PieChart, Pie, Sector, PieSectorShapeProps, Label, LabelList, LabelProps, Tooltip } from 'recharts';

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
  <Label {...props} fill={(props.index ?? 0) === 0 ? '#FFFFFF' : '#164B3E'} position="inside" />
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
        <div className='flex min-w-0 flex-col bg-[#ddf1ea] rounded-4xl p-5 sm:p-8 gap-5'>
            <p className='text-2xl text-black'>Class balance</p>
            <div className='flex min-w-0 flex-1 items-center'>
                <PieChart style={{ width: '100%', height: 280, minWidth: 0 }} responsive>
                    <Pie data={pieData} dataKey="value" innerRadius="60%" outerRadius="85%" shape={MyCustomPie}>
                        <LabelList dataKey="value" content={MyCustomLabel} formatter={(value) => formatPercentage(Number(value))} fontSize={12} />
                    </Pie>
                    <Tooltip formatter={(value) => Number(value).toLocaleString('en-US')} />
                </PieChart>
            </div>

            <div className='mt-auto flex flex-wrap gap-x-6 gap-y-2'>
                {pieData.map(entry => (
                    <p key={entry.name} className='text-gray-500'>
                        {formatPercentage(entry.value)} {entry.name.toLowerCase()}
                    </p>
                ))}
            </div>
        </div>
    );
}
