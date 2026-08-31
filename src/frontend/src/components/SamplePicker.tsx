import { useEffect, useState } from "react";
import { listSamples } from "../api";
import type { SampleApp } from "../types";

interface SamplePickerProps {
  onSelect: (sampleId: string) => void;
  loading: boolean;
  selectedId: string | null;
}

const RETRY_DELAY_MS = 4000;
const MAX_ATTEMPTS = 15; // ~60s of retrying - covers a cold Render free-tier wake-up

export function SamplePicker({ onSelect, loading, selectedId }: SamplePickerProps) {
  const [samples, setSamples] = useState<SampleApp[]>([]);
  const [gaveUp, setGaveUp] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    // A single fetch on mount used to fail permanently (and silently) if the backend
    // was still cold-starting - samples would then never show up until a fresh reload
    // happened to land after the backend had already woken up some other way. Retry
    // instead, since "backend takes a while to wake up" is an expected, temporary state.
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
          if (attemptNumber >= MAX_ATTEMPTS) {
            setGaveUp(true); // a real, non-transient failure - fail quietly, upload still works
            return;
          }
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

  if (gaveUp) return null;

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
