"use client";
import { inter } from '@/app/ui/fonts';
import type { SubmitEvent } from 'react'; 
import { useState } from 'react';
import { goonRequest } from '../api';

export default function Page() {
    const [name, setName] = useState("Mai");
    const [error, setError] = useState("");
    const [goon, setGoonRequest] = useState("");
    const [busy, setBusy] = useState(false);

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

            {busy && <p role="status">Sending request...</p>}
            {error && <p role="alert" className="break-words text-red-700">{error}</p>}
        </div>
    );
}

