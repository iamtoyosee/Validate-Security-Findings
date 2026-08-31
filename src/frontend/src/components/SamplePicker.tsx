import { useEffect, useState } from "react";
import { listSamples } from "../api";
import type { SampleApp } from "../types";

interface SamplePickerProps {
  onSelect: (sampleId: string) => void;
  loading: boolean;
  selectedId: string | null;
}

export function SamplePicker({ onSelect, loading, selectedId }: SamplePickerProps) {
  const [samples, setSamples] = useState<SampleApp[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    listSamples()
      .then(setSamples)
      .catch((err) => {
        // Fails quietly in the UI (upload still works fine without samples), but log
        // it - otherwise there's zero signal when this silently doesn't show up.
        console.error("Could not load sample apps:", err);
        setLoadError(err instanceof Error ? err.message : "Could not load sample apps.");
      });
  }, []);

  if (loadError) return null; // samples are a convenience, not core - fail quietly, upload still works
  if (samples.length === 0) return null;

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
