'use client';

import { useId, useState } from 'react';
import { ChevronDown, ChevronUp, ShieldAlert, ShieldCheck } from 'lucide-react';
import PredictionTable from './prediction-table';
import type { Analysis } from './types';

type Props = { result: Analysis | null };

export default function ManualResults({ result }: Props) {
    const [showDetails, setShowDetails] = useState(false);
    const detailsId = useId();

    if (!result) {
        return (
            <div className="w-full rounded-4xl bg-white p-8 sm:p-10">
                <p className="text-2xl text-black">Results</p>
                <p className="mt-5 text-xl text-gray-400">No results yet.</p>
            </div>
        );
    }

    const { summary, runtime } = result;
    const hasMalicious = summary.malicious > 0;
    const StatusIcon = hasMalicious ? ShieldAlert : ShieldCheck;
    const detailGroups = [
        {
            title: 'File & processing',
            fields: [
                ['File', summary.file_name ?? 'Unnamed upload'],
                ['Format', `${summary.input_format?.toUpperCase() ?? 'Unknown'}${summary.file_size_bytes !== null ? ` · ${(summary.file_size_bytes / 1024).toFixed(1)} KiB` : ''}`],
                ['Mode', 'Manual analysis · batch upload'],
                ['Analyzed at', new Date(summary.completed_at).toLocaleString(undefined, { timeZoneName: 'short' })],
                ['Processing / inference', `${summary.processing_ms.toFixed(2)} ms / ${summary.inference_ms.toFixed(2)} ms`],
            ],
        },
        {
            title: 'Model & preprocessing',
            fields: [
                ['Model', summary.model.name],
                ['Model ID', summary.model.id],
                ['Preprocessor', summary.preprocessor.name],
                ['Scaling', summary.preprocessor.scaling_applied ? 'Applied' : 'Not applied'],
                ['Malicious threshold', `Score ≥ ${summary.threshold.toFixed(2)}`],
                ['Mean malicious score', `${(summary.mean_score * 100).toFixed(2)}%`],
            ],
        },
        {
            title: 'Ground truth & agreement',
            fields: [
                ['Labeled / unlabeled', `${summary.ground_truth.provided_rows.toLocaleString()} / ${summary.ground_truth.missing_rows.toLocaleString()}`],
                ['Correct / incorrect', `${summary.ground_truth.correct.toLocaleString()} / ${summary.ground_truth.incorrect.toLocaleString()}`],
                ['Label agreement', summary.ground_truth.accuracy !== null ? `${(summary.ground_truth.accuracy * 100).toFixed(2)}%` : 'Not available without ground truth'],
            ],
        },
    ];

    function exportReport() {
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        const name = (summary.file_name ?? 'traffic').replace(/\.[^.]+$/, '').replace(/[\\/:*?"<>|]/g, '_');
        link.href = url;
        link.download = `${name}-analysis.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    return (
        <div className="flex min-w-0 w-full flex-col gap-5 rounded-4xl bg-white p-6 text-gray-600 sm:p-10">
            <div className="flex items-center gap-5 sm:gap-10">
                <div className={`flex shrink-0 items-center justify-center rounded-full p-5 sm:p-8 ${hasMalicious ? 'bg-red-50 text-red-700' : 'bg-[#BFE5D7] text-[#127A63]'}`}>
                    <StatusIcon fill="white" size={80} aria-hidden="true" />
                </div>
                <div>
                    <p className="text-xl text-gray-400">PREDICTION</p>
                    <p className="text-2xl sm:text-3xl">{hasMalicious ? 'Malicious traffic detected' : 'All records classified as benign'}</p>
                </div>
            </div>

            <dl className="grid grid-cols-2 gap-4 rounded-2xl bg-[#F2F5F4] p-4">
                <div><dt className="text-xl">Records / features</dt><dd className="text-2xl font-semibold">{summary.rows.toLocaleString()} / {summary.features}</dd></div>
                <div><dt className="text-xl">Benign / malicious</dt><dd className="text-2xl font-semibold">{summary.benign.toLocaleString()} / {summary.malicious.toLocaleString()}</dd></div>
                <div><dt className="text-xl">Mean confidence</dt><dd className="text-2xl font-semibold">{(summary.mean_confidence * 100).toFixed(2)}%</dd></div>
                <div><dt className="text-xl">Malicious records</dt><dd className="text-2xl font-semibold">{(summary.malicious_rate * 100).toFixed(2)}%</dd></div>
            </dl>

            <button type="button" onClick={exportReport} title="Download full analysis as JSON" className="mt-10 h-15 cursor-pointer rounded-4xl bg-gray-900 text-2xl text-amber-50">Export</button>
            <button
                type="button" onClick={() => setShowDetails(!showDetails)}
                aria-expanded={showDetails} aria-controls={detailsId}
                className="flex w-fit cursor-pointer items-center gap-2 rounded-full bg-[#F0F8F4] px-5 py-3 text-lg text-[#127A63] hover:bg-[#DDF1EA]"
            >
                {showDetails ? 'Hide details' : 'Show details'}
                {showDetails ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
            </button>

            <div id={detailsId} hidden={!showDetails} className="min-w-0 space-y-5">
                <h3 className="text-2xl font-semibold text-[#3D3D3D]">Analysis details</h3>
                {detailGroups.map((group) => (
                    <section key={group.title} className="rounded-3xl bg-[#F2F5F4] p-5 sm:p-6">
                        <h4 className="mb-4 text-xl font-semibold text-[#127A63]">{group.title}</h4>
                        <dl className="grid gap-4 sm:grid-cols-2">
                            {group.fields.map(([label, value]) => (
                                <div key={label} className="min-w-0">
                                    <dt className="mb-1 text-base text-gray-500">{label}</dt>
                                    <dd className="break-words text-lg text-[#3D3D3D]">{value}</dd>
                                </div>
                            ))}
                        </dl>
                    </section>
                ))}
                <details className="rounded-2xl border border-[#E3EBE7] p-5 text-base">
                    <summary className="cursor-pointer font-medium text-[#127A63]">Technical details</summary>
                    <dl className="mt-4 space-y-3">
                        <div><dt>Model SHA-256</dt><dd className="break-all font-mono text-sm">{summary.model.sha256}</dd></div>
                        <div><dt>Objective</dt><dd>{summary.model.objective}</dd></div>
                        <div><dt>Preprocessing</dt><dd>{summary.preprocessor.steps.join(' → ')}</dd></div>
                        <div><dt>Runtime</dt><dd>XGBoost {runtime.xgboost} · NumPy {runtime.numpy}</dd></div>
                    </dl>
                </details>
                <p className="text-base text-gray-500">Agreement covers only records with ground-truth labels supplied in the upload.</p>
                <PredictionTable key={summary.completed_at} rows={result.results} />
            </div>
        </div>
    );
}
