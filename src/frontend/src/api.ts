import type { ScanResponse } from "./types";

// VITE_API_URL: the deployed backend's base URL, e.g. "https://my-backend.onrender.com".
// Falls back to localhost so `npm run dev` keeps working with no setup.
const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const SCAN_URL = `${API_BASE}/api/scan`;

/** POSTs the selected folder's files to the scan endpoint, preserving relative paths. */
export async function scanCodebase(files: File[]): Promise<ScanResponse> {
  const formData = new FormData();
  for (const file of files) {
    formData.append("files", file, file.webkitRelativePath || file.name);
  }

  const response = await fetch(SCAN_URL, { method: "POST", body: formData });

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
