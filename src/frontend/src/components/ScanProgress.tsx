import { useEffect, useState } from "react";
import { Icon } from "./ui";

// Elapsed-time-based staging, not real backend progress - the API is one blocking
// request with no progress events (see the "Real scan progress" roadmap item). The
// thresholds exist so a cold free-tier backend (30-60s wake) doesn't read as frozen.
const STAGES: { afterSeconds: number; label: string }[] = [
  { afterSeconds: 0, label: "Sending codebase" },
  { afterSeconds: 4, label: "Waking up the server" },
  { afterSeconds: 20, label: "Running Semgrep" },
  { afterSeconds: 35, label: "Building the call graph" },
  { afterSeconds: 45, label: "Tracing reachability" },
];

export function ScanProgress({ target, onCancel }: { target: string; onCancel: () => void }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => setElapsed((Date.now() - start) / 1000), 250);
    return () => clearInterval(id);
  }, []);

  const current = STAGES.reduce((idx, s, i) => (elapsed >= s.afterSeconds ? i : idx), 0);

  return (
    <div className="progress-card">
      <div className="progress-head">
        <span className="spinner spinner-lg" />
        <div>
          <h2>Scanning {target}</h2>
          <span className="sr-only" role="status" aria-live="polite">
            {STAGES[current].label}
          </span>
          <p className="muted">{Math.floor(elapsed)}s elapsed · stages are estimated from elapsed time</p>
        </div>
      </div>
      <ol className="stages">
        {STAGES.map((s, i) => (
          <li key={s.label} className={i < current ? "done" : i === current ? "active" : ""}>
            <span className="stage-mark">{i < current ? <Icon name="check" size={12} /> : null}</span>
            {s.label}
          </li>
        ))}
      </ol>
      <button type="button" className="btn btn-ghost" onClick={onCancel}>
        Cancel
      </button>
    </div>
  );
}
