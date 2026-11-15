"use client";

import { useId, useState, type SubmitEvent } from "react";
import FileUploadOutlinedIcon from "@mui/icons-material/FileUploadOutlined";

type Analysis = {
    summary: { rows: number; features: number; benign: number; malicious: number };
    results: { row: number; label: string; probability_malicious: number }[];
};

const API_URL = (
    process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export default function InputPrediction() {
    const fileInputId = useId();
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
        <div className='flex flex-1 flex-col bg-[#FFFFFF] w-full h-full rounded-4xl px-10 py-10 gap-5 basis-1/2'>
            <p className='text-2xl text-black'>Input</p>
            <p className='text-xl text-gray-400'>Upload a CSV or JSON file to analyze traffic records.</p>

            <div className="space-y-2 text-gray-500">
                <p className='text-2xl text-gray-400'>Traffic file</p>
                <form onSubmit={analyze} className="flex flex-col items-center gap-4">
                    <div className="flex flex-row w-full items-center gap-2">
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
                            className="peer sr-only"
                            id={fileInputId}
                            aria-describedby={`${fileInputId}-name`}
                        />

                        <div className="bg-[#F2F5F4] h-15 w-full flex justify-center items-center rounded-2xl">
                            <span id={`${fileInputId}-name`} className=" text-xl text-gray-400" >
                                {file?.name ?? "No file selected yet"}
                            </span>
                        </div>

                        <label
                            htmlFor={fileInputId}
                            className="flex cursor-pointer w-15 h-15 aspect-square items-center justify-center rounded-2xl bg-[#ddf1ea] text-emerald-700"
                        >
                            <FileUploadOutlinedIcon fontSize="large" />
                        </label>
                    </div>
                    
                    <div className="h-10"></div>
                    <button
                        type="submit"
                        disabled={!file || loading}
                        className="rounded-4xl cursor-pointer bg-gray-900 text-amber-50 px-4 py-2 w-full text-2xl"
                    >
                        {loading ? "Analyzing..." : "Run analysis"}
                    </button>
                </form>
                <p className='text-xl text-gray-400'>Accepts pre-extracted N-BaIoT feature records. PCAP files are not supported.</p>
                {error && <p role="alert">{error}</p>}
                {result && (
                    <section aria-live="polite" className="overflow-x-auto">
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
            </div>
        </div>
    );
}


