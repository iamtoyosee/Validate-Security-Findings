import { useEffect, useState } from "react";

// Elapsed-time-based staging, not real backend progress - the API is one blocking
// request with no progress events. These thresholds exist to keep a cold Render
// free-tier backend (30-60s wake time) from reading as frozen, not to claim precision.
const STAGES: { afterSeconds: number; label: string }[] = [
  { afterSeconds: 0, label: "Uploading codebase…" },
  { afterSeconds: 4, label: "Waking up the server (first request can take a moment)…" },
  { afterSeconds: 20, label: "Running Semgrep…" },
  { afterSeconds: 35, label: "Building the call graph…" },
  { afterSeconds: 45, label: "Tracing reachability…" },
];

export function ScanProgress() {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => setElapsed((Date.now() - start) / 1000), 250);
    return () => clearInterval(id);
  }, []);

  const stage = [...STAGES].reverse().find((s) => elapsed >= s.afterSeconds) ?? STAGES[0];

  return (
    <div className="scan-progress" role="status" aria-live="polite">
      <span className="scan-spinner" aria-hidden="true" />
      <span className="scan-progress-label">{stage.label}</span>
    </div>
  );
}
