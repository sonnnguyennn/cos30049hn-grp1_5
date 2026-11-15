'use client';

import type { Analysis } from './types';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

type Props = {
    result: Analysis | null;
};

export default function ManualResults({ result }: Props) {
    const summary = result?.summary;
    const hasMalicious = (summary?.malicious ?? 0) > 0;
    const StatusIcon = hasMalicious ? ShieldAlert : ShieldCheck;

    return (
        <div className='flex w-full h-full flex-col bg-[#FFFFFF] rounded-4xl px-10 py-10 gap-5'>
            <p className='text-2xl text-black'>Results</p>
            <div aria-live="polite" className="min-w-0 space-y-5 text-gray-600">
                {result && summary ? (
                    <>
                        <div className={`flex items-center gap-3 rounded-2xl p-4 ${hasMalicious ? 'bg-red-50 text-red-700' : 'bg-[#BFE5D7] text-[#127A63]'}`}>
                            <StatusIcon size={36} aria-hidden="true" className="shrink-0" />
                            <p className="font-semibold">
                                {hasMalicious ? 'Malicious traffic detected' : 'All records classified as benign'}
                            </p>
                        </div>

                        <dl className="grid grid-cols-2 gap-4 rounded-2xl bg-[#F2F5F4] p-4">
                            <div><dt className="text-sm">Records / features</dt><dd className="text-xl font-semibold">{summary.rows.toLocaleString()} / {summary.features}</dd></div>
                            <div><dt className="text-sm">Benign / malicious</dt><dd className="text-xl font-semibold">{summary.benign.toLocaleString()} / {summary.malicious.toLocaleString()}</dd></div>
                            <div><dt className="text-sm">Mean confidence</dt><dd className="text-xl font-semibold">{(summary.mean_confidence * 100).toFixed(2)}%</dd></div>
                            <div><dt className="text-sm">Malicious records</dt><dd className="text-xl font-semibold">{(summary.malicious_rate * 100).toFixed(2)}%</dd></div>
                        </dl>

                        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm [&_dd]:break-words [&_dt]:font-semibold">
                            <dt>File</dt><dd>{summary.file_name ?? 'Unnamed upload'} ({summary.input_format?.toUpperCase() ?? 'Unknown format'}{summary.file_size_bytes !== null ? `, ${(summary.file_size_bytes / 1024).toFixed(1)} KiB` : ''})</dd>
                            <dt>Mode</dt><dd>Manual analysis · batch upload</dd>
                            <dt>Analyzed at</dt><dd>{new Date(summary.completed_at).toLocaleString(undefined, { timeZoneName: 'short' })}</dd>
                            <dt>Processing time</dt><dd>{summary.processing_ms.toFixed(2)} ms · inference {summary.inference_ms.toFixed(2)} ms</dd>
                            <dt>Model</dt><dd>{summary.model.name}<br /><span className="font-mono text-xs">{summary.model.id}</span></dd>
                            <dt>Preprocessor</dt><dd>{summary.preprocessor.name}; scaling {summary.preprocessor.scaling_applied ? 'applied' : 'not applied'}</dd>
                            <dt>Decision threshold</dt><dd>Malicious score ≥ {summary.threshold.toFixed(2)}</dd>
                            <dt>Mean malicious score</dt><dd>{(summary.mean_score * 100).toFixed(2)}%</dd>
                            <dt>Ground truth</dt><dd>{summary.ground_truth.provided_rows > 0 ? `${summary.ground_truth.provided_rows} labeled; ${summary.ground_truth.missing_rows} unlabeled (from upload)` : 'Not provided'}</dd>
                            <dt>Label agreement</dt><dd>{summary.ground_truth.accuracy !== null ? `${(summary.ground_truth.accuracy * 100).toFixed(2)}% (${summary.ground_truth.correct} correct, ${summary.ground_truth.incorrect} incorrect)` : 'Unavailable without ground truth'}</dd>
                        </dl>
                        <p className="text-xs text-gray-500">
                            Score is the model&apos;s probability of malicious traffic. Confidence is the probability assigned to the predicted class.
                            Ground truth comes from the upload; label agreement covers only labeled rows.
                        </p>

                        <details className="text-sm">
                            <summary className="cursor-pointer font-semibold">Model and preprocessing details</summary>
                            <dl className="mt-2 space-y-2 [&_dt]:font-semibold">
                                <div><dt>Model SHA-256</dt><dd className="break-all font-mono text-xs">{summary.model.sha256}</dd></div>
                                <div><dt>Objective</dt><dd>{summary.model.objective}</dd></div>
                                <div><dt>Preprocessing steps</dt><dd>{summary.preprocessor.steps.join(' → ')}</dd></div>
                                <div><dt>Runtime</dt><dd>XGBoost {result.runtime.xgboost} · NumPy {result.runtime.numpy}</dd></div>
                            </dl>
                        </details>

                        {summary.rows > 100 && <p className="text-sm">Showing the first 100 of {summary.rows.toLocaleString()} predictions. Summary covers every row.</p>}
                        <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm [&_th]:whitespace-nowrap [&_th]:p-2 [&_td]:p-2">
                            <caption className="sr-only">Predictions with scores and optional ground truth</caption>
                            <thead>
                                <tr><th>Sample</th><th>Prediction</th><th>Malicious score</th><th>Confidence</th><th>Ground truth</th><th>Match</th></tr>
                            </thead>
                            <tbody>
                                {result.results.slice(0, 100).map((row) => (
                                    <tr key={row.row}>
                                        <td><span className="block max-w-48 break-words">{row.sample_name}</span><span className="text-xs text-gray-400">Row {row.row}</span></td>
                                        <td className={row.label === 'malicious' ? 'text-red-700' : 'text-emerald-700'}>{row.label}</td>
                                        <td>{(row.score * 100).toFixed(4)}%</td>
                                        <td>{(row.confidence * 100).toFixed(4)}%</td>
                                        <td>{row.ground_truth ?? 'Not provided'}</td>
                                        <td>{row.correct === null ? '—' : row.correct ? 'Correct' : 'Incorrect'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        </div>
                    </>
                ) : (
                    <div className='flex flex-col gap-5'>
                        <p className='text-xl text-gray-400'>No results yet.</p>
                    </div>
                )}
            </div>
        </div>
    );
}


