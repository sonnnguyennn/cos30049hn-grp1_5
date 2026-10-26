"use client";
import { inter } from '@/app/ui/fonts';

import { useState } from "react";

type LogEntry = {
  id: number;
  created_at: string;
  event: string;
  message: string;
  filename: string | null;
};

function isLogEntry(value: unknown): value is LogEntry {
  if (typeof value !== "object" || value === null) return false;
  return (
    "id" in value && typeof value.id === "number" &&
    "created_at" in value && typeof value.created_at === "string" &&
    "event" in value && typeof value.event === "string" &&
    "message" in value && typeof value.message === "string" &&
    "filename" in value &&
    (typeof value.filename === "string" || value.filename === null)
  );
}

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function loadLogs() {
    setBusy(true);
    setError("");
    try {
      const response = await fetch(API_URL + "/logs?limit=50", {
        cache: "no-store",
      });
      if (!response.ok) throw new Error("Could not load logs: HTTP " + response.status);
      const data: unknown = await response.json();
      if (!Array.isArray(data) || !data.every(isLogEntry)) {
        throw new Error("Unexpected log response from the API");
      }
      setLogs(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-5xl space-y-4 p-6">
      <h1 className="text-2xl font-bold">Activity logs</h1>
      <button
        type="button"
        onClick={loadLogs}
        disabled={busy}
        className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50"
      >
        {busy ? "Loading..." : "Load / refresh logs"}
      </button>
      {error && <p role="alert" className="text-red-600">{error}</p>}
      {logs === null && <p>Click the button to load recent logs.</p>}
      {logs?.length === 0 && <p>No logs yet. Inspect a file on the practice page first.</p>}
      {logs !== null && logs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr>
                <th className="border p-2">Time (UTC)</th>
                <th className="border p-2">Event</th>
                <th className="border p-2">File</th>
                <th className="border p-2">Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td className="border p-2">{log.created_at}</td>
                  <td className="border p-2">{log.event}</td>
                  <td className="border p-2">{log.filename ?? "—"}</td>
                  <td className="border p-2">{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

