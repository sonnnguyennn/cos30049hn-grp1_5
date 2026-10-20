const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/,"")

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function requestJson(
  path: string,
  options?: RequestInit,
): Promise<unknown> {
  const response = await fetch(`${API_URL}${path}`, options);
  let data: unknown;

  try {
    data = await response.json();
  } catch {
    throw new Error(`Expected JSON from the API (HTTP ${response.status})`);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

export async function goonRequest(name:string): Promise<string> {
    const data = await requestJson("/goon", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({name})
    });
    if (!isRecord(data) || typeof data.message !== "string") {
    throw new Error("Unexpected gooning response");
  }
    return data.message;
}
