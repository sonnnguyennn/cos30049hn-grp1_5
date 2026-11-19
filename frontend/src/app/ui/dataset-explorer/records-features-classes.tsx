'use client';

const types = [
  { name: 'Records', description: 'After validation' },
  { name: 'Features', description: 'Locked feature schema' },
  { name: 'Classes', description: 'Benign, Malicious' },
];

type SummaryField = {
  label: string;
  value: number | null;
};

type Props = {
  currentDataset: number;
  data: SummaryField[][];
};

export default function RecordsFeaturesClasses({ currentDataset, data }: Props) {
  const summary = data[currentDataset - 1];

  return (
    <div className="grid min-w-0 grid-cols-1 gap-5 @min-[40rem]:grid-cols-3">
      {types.map(({ name, description }) => {
        const value = summary?.find((field) => field.label === name)?.value;

        return (
          <div
            key={name}
            className="flex min-w-0 flex-col justify-center gap-1.5 rounded-4xl bg-white px-5 py-5 @min-[64rem]:px-10"
          >
            <p className="text-2xl text-gray-500">{name}</p>
            <p className="text-2xl font-semibold text-gray-900">
              {value?.toLocaleString('en-US') ?? '—'}
            </p>
            <p className="text-xl text-gray-500">{description}</p>
          </div>
        );
      })}
    </div>
  );
}
