import type { ScanResponse } from "./types";

const SCAN_URL = "http://localhost:8000/api/scan";

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
