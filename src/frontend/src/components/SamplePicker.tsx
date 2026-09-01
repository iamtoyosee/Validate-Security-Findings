import { useEffect, useState } from "react";
import { listSamples } from "../api";
import type { SampleApp } from "../types";

interface SamplePickerProps {
  onSelect: (sampleId: string) => void;
  loading: boolean;
  selectedId: string | null;
}

const RETRY_DELAY_MS = 4000;

export function SamplePicker({ onSelect, loading, selectedId }: SamplePickerProps) {
  const [samples, setSamples] = useState<SampleApp[]>([]);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    // A single fetch on mount used to fail permanently (and silently) if the backend
    // was cold-starting. A capped retry (originally 60s) turned out to still give up
    // before some cold starts finish - the backend would then only get woken up by an
    // unrelated action (an upload has no such timeout), matching exactly "works after
    // I upload something." Retry indefinitely instead: there's no real cost to quietly
    // polling every few seconds while someone's on the page, and it removes the failure
    // mode entirely rather than just widening the window and hoping it's enough.
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const tryLoad = (attemptNumber: number) => {
      listSamples()
        .then((result) => {
          if (!cancelled) setSamples(result);
        })
        .catch((err) => {
          console.error(`Could not load sample apps (attempt ${attemptNumber}):`, err);
          if (cancelled) return;
          setAttempt(attemptNumber);
          timer = setTimeout(() => tryLoad(attemptNumber + 1), RETRY_DELAY_MS);
        });
    };
    tryLoad(1);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  if (samples.length === 0) {
    return attempt > 0 ? <p className="sample-picker-label">Waking up the sample apps…</p> : null;
  }

  return (
    <div className="sample-picker">
      <p className="sample-picker-label">Try a sample codebase, no upload needed:</p>
      <div className="sample-grid">
        {samples.map((sample) => (
          <button
            key={sample.id}
            type="button"
            className={`sample-card${selectedId === sample.id ? " sample-card-selected" : ""}`}
            onClick={() => onSelect(sample.id)}
            disabled={loading}
          >
            <span className="sample-card-name">{sample.name}</span>
            <span className="sample-card-description">{sample.description}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
