import type { ScanResponse, SampleApp } from "./types";

// VITE_API_URL: the deployed backend's base URL, e.g. "https://my-backend.onrender.com".
// Falls back to localhost so `npm run dev` keeps working with no setup.
const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function parseScanResponse(response: Response): Promise<ScanResponse> {
  if (!response.ok) {
    let detail = `Scan failed (HTTP ${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // non-JSON error body - fall back to the generic message above
    }
    throw new Error(detail);
  }
  return response.json();
}

/** POSTs the selected folder's files to the scan endpoint, preserving relative paths. */
export async function scanCodebase(files: File[]): Promise<ScanResponse> {
  const formData = new FormData();
  for (const file of files) {
    formData.append("files", file, file.webkitRelativePath || file.name);
  }
  const response = await fetch(`${API_BASE}/api/scan`, { method: "POST", body: formData });
  return parseScanResponse(response);
}

export async function listSamples(): Promise<SampleApp[]> {
  const response = await fetch(`${API_BASE}/api/samples`);
  if (!response.ok) throw new Error(`Could not load sample apps (HTTP ${response.status}).`);
  return response.json();
}

export async function scanSample(sampleId: string): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE}/api/scan-sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_id: sampleId }),
  });
  return parseScanResponse(response);
}
