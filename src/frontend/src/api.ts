import type { SampleApp, ScanOptions, ScanResponse, UploadEntry } from "./types";

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

/**
 * POSTs the preflighted files to the scan endpoint, preserving relative paths.
 * `options` rides along as a JSON form field - the backend ignores it today
 * (FastAPI drops undeclared form fields) and can start honoring it per-option.
 */
export async function scanCodebase(entries: UploadEntry[], options: ScanOptions, signal?: AbortSignal): Promise<ScanResponse> {
  const formData = new FormData();
  for (const { path, file } of entries) {
    formData.append("files", file, path);
  }
  formData.append("options", JSON.stringify(options));
  const response = await fetch(`${API_BASE}/api/scan`, { method: "POST", body: formData, signal });
  return parseScanResponse(response);
}

export async function listSamples(): Promise<SampleApp[]> {
  const response = await fetch(`${API_BASE}/api/samples`);
  if (!response.ok) throw new Error(`Could not load sample apps (HTTP ${response.status}).`);
  return response.json();
}

/** `options` is an extra JSON key; ScanSampleRequest (pydantic) ignores unknown keys. */
export async function scanSample(sampleId: string, options: ScanOptions, signal?: AbortSignal): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE}/api/scan-sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_id: sampleId, options }),
    signal,
  });
  return parseScanResponse(response);
}
