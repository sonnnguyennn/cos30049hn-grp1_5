"use client";
import { inter } from '@/app/ui/fonts';
import type { SubmitEvent } from 'react'; 
import { useState } from 'react';
import { goonRequest, inspectFile } from '../api';
import type { FileInfo } from "../api";

export default function Page() {
    const [name, setName] = useState("Mai");
    const [error, setError] = useState("");
    const [goon, setGoonRequest] = useState("");
    const [busy, setBusy] = useState(false);
    const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
    const [file, setFile] = useState<File | null>(null);

    async function handleGoonRequest(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault();
        setError("");
        setGoonRequest("");
        setBusy(true);
        try {
            setGoonRequest(await goonRequest(name));
        } catch (err) {
            setError(err instanceof Error ? err.message : "Request failed");
        } finally {
        setBusy(false);
        }
    }

    async function handleUpload(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault();
        setError("");
        setFileInfo(null);
        if (!file) {
        setError("Choose a file first");
        return;
        }
        setBusy(true);
        try {
        setFileInfo(await inspectFile(file));
        } catch (err) {
        setError(err instanceof Error ? err.message : "Upload failed");
        } finally {
        setBusy(false);
        }
    }

    return (
        <div>
            <div className={`${inter.className} text-4xl text-black`}>Goon Corner</div>
            
            <form onSubmit={handleGoonRequest}
                className="space-y-2 p-4">
                <h2 className="text-lg font-semibold text-black">Send JSON</h2>
                <label htmlFor="greeting-name" className="block text-black">Your name</label>
                <input id="greeting-name" value={name} required maxLength={50}
                onChange={(event) => setName(event.currentTarget.value)}
                className="block w-full rounded border p-2 text-black" />
                <button type="submit" disabled={busy}
                className="rounded bg-blue-700 px-4 py-2 text-white disabled:opacity-50">
                Send goon request
                </button>
                {goon && <p className="block w-full rounded border p-2 text-black" role="status">{goon}</p>}
            </form>

            <form onSubmit={handleUpload}
                className="space-y-2 p-4">
                <h2 className="text-lg font-semibold text-black">Upload a file</h2>
                <label htmlFor="capture-file" className="block text-black">Choose a file</label>
                <input id="capture-file" type="file" 
                onChange={(event) => setFile(event.currentTarget.files?.[0] ?? null)}
                className="block w-full text-black" />
                <button type="submit" disabled={busy}
                className="rounded bg-blue-700 px-4 py-2 text-white disabled:opacity-50">
                Inspect upload
                </button>
                <p className="text-sm text-black">Reports file information. Limit: 10 MiB.</p>
                {fileInfo && (
                <dl role="status" className=" text-black">
                    <dt>Filename</dt><dd>{fileInfo.filename}</dd>
                    <dt>Bytes</dt><dd>{fileInfo.size_bytes}</dd>
                    <dt>Content type</dt><dd>{fileInfo.content_type ?? "Unknown"}</dd>
                </dl>
                )}
            </form>

            {busy && <p role="status">Sending request...</p>}
            {error && <p role="alert" className="break-words text-red-700">{error}</p>}
        </div>
    );
}

