"use client";

import { useState, type SubmitEvent } from "react";

type Analysis = {
    summary: { rows: number; features: number; benign: number; malicious: number };
    results: { row: number; label: string; probability_malicious: number }[];
};

const API_URL = (
    process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export default function InputPrediction() {
    const [file, setFile] = useState<File | null>(null);
    const [result, setResult] = useState<Analysis | null>(null);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    async function analyze(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault();
        if (!file || loading) return;
        setLoading(true);
        setResult(null);
        setError("");

        try {
            const body = new FormData();
            body.append("file", file);
            const response = await fetch(`${API_URL}/predict`, {
                method: "POST",
                body,
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(
                    typeof data.detail === "string" ? data.detail : "Analysis failed"
                );
            }
            setResult(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Cannot contact the API");
        } finally {
            setLoading(false);
        }
    }
    return (
        <div className='flex flex-col bg-[#FFFFFF] w-full h-full rounded-4xl px-10 py-10 gap-5'>
            <p className='text-2xl text-black'>Input</p>
            <p className='text-xl text-gray-400'>Choose a sample, upload a CSV file or paste a JSON record.</p>
            <main className="space-y-4 p-6 text-gray-500">
                <h1 className="text-2xl font-semibold">Analyze traffic file</h1>
                <form onSubmit={analyze} className="flex gap-4">
                    <input
                        type="file"
                        accept=".csv,.json"
                        aria-label="Traffic CSV or JSON"
                        disabled={loading}
                        onChange={(event) => {
                            setFile(event.target.files?.[0] ?? null);
                            setResult(null);
                            setError("");
                        }}
                    />
                    <button type="submit" disabled={!file || loading}>
                        {loading ? "Analyzing..." : "Analyze"}
                    </button>
                </form>
                {error && <p role="alert">{error}</p>}
                {result && (
                    <section aria-live="polite">
                        <p>
                            {result.summary.rows} rows: {result.summary.benign} benign,
                            {" "}{result.summary.malicious} malicious
                        </p>
                        {result.summary.rows > 100 && <p>Showing the first 100 predictions.</p>}
                        <table>
                            <thead>
                                <tr><th>Row</th><th>Prediction</th><th>Malicious probability</th></tr>
                            </thead>
                            <tbody>
                                {result.results.slice(0, 100).map((row) => (
                                    <tr key={row.row}>
                                        <td>{row.row}</td>
                                        <td>{row.label}</td>
                                        <td>{(row.probability_malicious * 100).toFixed(4)}%</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </section>
                )}
            </main>
        </div>
    );
}


