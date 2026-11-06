"use client";
import { inter } from '@/app/ui/fonts';

import {
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const results = [
  { model: "LR", accuracy: 92.4, macroF1: 90.8, inferenceMs: 1.2 },
  { model: "RF", accuracy: 97.1, macroF1: 96.2, inferenceMs: 4.8 },
  { model: "SVM", accuracy: 95.6, macroF1: 94.3, inferenceMs: 8.5 },
];

export default function BenchmarksPage() {
  return (
    <main className="mx-auto max-w-5xl space-y-6 p-6">
      <h1 className="text-2xl font-bold text-black">Model benchmarks</h1>

      <p className='text-black'>
        Demo data. LR = Logistic Regression, RF = Random Forest.
      </p>

      <section className="rounded-lg border p-4 border-black">
        <h2 className="mb-4 text-lg font-semibold text-black">
          Prediction scores — higher is better
        </h2>

        <div style={{ width: "100%", height: 320 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={results}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />

              <XAxis dataKey="model" />
              <YAxis domain={[0, 100]} unit="%" />

              <Tooltip />
              <Legend />

              <Bar
                dataKey="accuracy"
                name="Accuracy (%)"
                fill="#2563eb"
              />

              <Bar
                dataKey="macroF1"
                name="Macro F1 (%)"
                fill="#16a34a"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="rounded-lg border p-4 border-black">
        <h2 className="mb-4 text-lg font-semibold text-black">
            Inference time — lower is better
        </h2>

        <div style={{ width: "100%", height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
            <BarChart data={results}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />

                <XAxis dataKey="model" />
                <YAxis unit=" ms" />

                <Tooltip />

                <Bar
                dataKey="inferenceMs"
                name="Inference time (ms)"
                fill="#9333ea"
                />
            </BarChart>
            </ResponsiveContainer>
        </div>
        </section>
    </main>
  );
}

