import { useEffect, useMemo, useRef, useState } from "react";
import { listSamples } from "../api";
import { timeAgo } from "../lib/format";
import type { HistoryEntry } from "../lib/storage";
import type { ExcludeReason, PreflightReport } from "../lib/uploadSafety";
import {
  REASON_LABEL,
  entriesFromDataTransfer,
  entriesFromFileList,
  formatBytes,
  parseGlobs,
  runPreflight,
} from "../lib/uploadSafety";
import type { SampleApp, ScanOptions, ScannerId, UploadEntry } from "../types";
import { Card, EmptyState, Icon, StatusTag } from "./ui";

type Source = "sample" | "upload" | "import";

export type ScanRequest =
  | { kind: "sample"; sample: SampleApp }
  | { kind: "upload"; report: PreflightReport; redact: boolean };

interface NewScanProps {
  options: ScanOptions;
  onOptionsChange: (o: ScanOptions) => void;
  onScan: (req: ScanRequest) => void;
  history: HistoryEntry[];
  onOpenHistory: (entry: HistoryEntry) => void;
  onOpenRoadmap: () => void;
}

export function NewScan({ options, onOptionsChange, onScan, history, onOpenHistory, onOpenRoadmap }: NewScanProps) {
  const [source, setSource] = useState<Source>("sample");
  const [samples, setSamples] = useState<SampleApp[]>([]);
  const [samplesWaking, setSamplesWaking] = useState(false);
  const [selectedSample, setSelectedSample] = useState<string | null>(null);
  const [entries, setEntries] = useState<UploadEntry[] | null>(null);
  // The report remembers which selection + exclusions it was computed for, so a
  // stale one (new folder picked, preflight still running) is never scannable.
  const [preflight, setPreflight] = useState<{ entries: UploadEntry[]; globs: string[]; report?: PreflightReport; error?: string } | null>(null);
  const [redact, setRedact] = useState(true);
  const [excludeText, setExcludeText] = useState(options.exclude_globs.join("\n"));

  useSampleLoader(setSamples, setSamplesWaking);

  // Re-run preflight whenever the selection or exclusions change.
  const globs = useMemo(() => parseGlobs(excludeText), [excludeText]);
  useEffect(() => {
    if (!entries) return;
    let cancelled = false;
    runPreflight(entries, globs)
      .then((report) => !cancelled && setPreflight({ entries, globs, report }))
      .catch((err) => {
        if (!cancelled) setPreflight({ entries, globs, error: err instanceof Error ? err.message : "Couldn't read the selected files." });
      });
    return () => {
      cancelled = true;
    };
  }, [entries, globs]);
  const fresh = preflight && preflight.entries === entries && preflight.globs === globs ? preflight : null;
  const report = fresh?.report ?? null;
  const checking = !!entries && !fresh;

  const updateGlobs = (text: string) => {
    setExcludeText(text);
    onOptionsChange({ ...options, exclude_globs: parseGlobs(text) });
  };

  const sample = samples.find((s) => s.id === selectedSample);
  const ready =
    source === "sample" ? !!sample : source === "upload" ? !!report && report.blockers.length === 0 : false;

  const start = () => {
    if (source === "sample" && sample) onScan({ kind: "sample", sample });
    if (source === "upload" && report) onScan({ kind: "upload", report, redact });
  };

  return (
    <div className="newscan">
      <div className="newscan-intro">
        <h1>Validate scanner findings</h1>
        <p>
          Run a scan, collapse duplicate rule hits, and trace which findings are actually reachable from an entry point
          — so engineers spend time on the few that matter.
        </p>
      </div>

      <div className="newscan-grid">
        <div className="newscan-main">
          <Card title="1 · Choose a codebase">
            <div className="segmented" role="tablist">
              <SegButton active={source === "sample"} onClick={() => setSource("sample")} icon="box">
                Sample apps
              </SegButton>
              <SegButton active={source === "upload"} onClick={() => setSource("upload")} icon="folder">
                Upload folder
              </SegButton>
              <SegButton active={source === "import"} onClick={() => setSource("import")} icon="file">
                Import results
              </SegButton>
            </div>

            {source === "sample" && (
              <SampleGrid samples={samples} waking={samplesWaking} selected={selectedSample} onSelect={setSelectedSample} />
            )}

            {source === "upload" && (
              <>
                <Dropzone onEntries={setEntries} hasSelection={!!entries} />
                {checking && (
                  <div className="loading-line">
                    <span className="spinner" /> Checking files…
                  </div>
                )}
                {fresh?.error && (
                  <div className="notice notice-error preflight-error">
                    <Icon name="alert" /> {fresh.error}
                  </div>
                )}
                {report && <PreflightReview report={report} redact={redact} onRedactChange={setRedact} />}
              </>
            )}

            {source === "import" && (
              <EmptyState
                icon="file"
                title="Bring your own scanner output"
                action={<StatusTag status="planned" onClick={onOpenRoadmap} />}
              >
                <p>
                  Upload SARIF or Semgrep JSON from CI alongside the codebase, and skip straight to validation. Useful when
                  scans already run in your pipeline.
                </p>
              </EmptyState>
            )}
          </Card>

          {history.length > 0 && (
            <Card title="Recent scans">
              <ul className="recent">
                {history.slice(0, 4).map((h) => (
                  <li key={h.id}>
                    <button type="button" className="recent-row" onClick={() => onOpenHistory(h)}>
                      <Icon name={h.target.kind === "sample" ? "box" : "folder"} />
                      <span className="recent-label">{h.target.label}</span>
                      <span className="recent-meta">
                        {h.result.findings.length} findings ·{" "}
                        {h.result.reachability.filter((r) => r.status === "reachable").length} reachable
                      </span>
                      <span className="recent-time">{timeAgo(h.startedAt)}</span>
                      <Icon name="chevronRight" className="muted" />
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <aside className="newscan-side">
          <ScanSettings
            options={options}
            onChange={onOptionsChange}
            excludeText={excludeText}
            onExcludeChange={updateGlobs}
            showExcludes={source === "upload"}
            onOpenRoadmap={onOpenRoadmap}
          />
          <div className="run-box">
            <button type="button" className="btn btn-primary btn-block" disabled={!ready} onClick={start}>
              <Icon name="play" size={14} />
              {source === "sample" && sample
                ? `Scan ${sample.name}`
                : source === "upload" && report
                  ? `Scan ${report.included.length} files`
                  : "Run scan"}
            </button>
            <p className="run-note">
              <Icon name="lock" size={12} />
              {source === "upload"
                ? "Only files listed under “Will upload” leave your browser. The server deletes them after the scan."
                : "Sample apps are bundled with the server — nothing is uploaded."}
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}

function SegButton({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: "box" | "folder" | "file"; children: string }) {
  return (
    <button type="button" role="tab" aria-selected={active} className={active ? "active" : ""} onClick={onClick}>
      <Icon name={icon} size={14} />
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------

const RETRY_DELAY_MS = 4000;

function useSampleLoader(setSamples: (s: SampleApp[]) => void, setWaking: (w: boolean) => void) {
  useEffect(() => {
    // Retry indefinitely: a free-tier backend can take a minute to cold-start, and a
    // capped retry used to give up right before it woke (see git history).
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const tryLoad = (attempt: number) => {
      listSamples()
        .then((result) => {
          if (cancelled) return;
          setSamples(result);
          setWaking(false);
        })
        .catch((err) => {
          console.error(`Could not load sample apps (attempt ${attempt}):`, err);
          if (cancelled) return;
          setWaking(true);
          timer = setTimeout(() => tryLoad(attempt + 1), RETRY_DELAY_MS);
        });
    };
    tryLoad(1);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [setSamples, setWaking]);
}

function SampleGrid({
  samples,
  waking,
  selected,
  onSelect,
}: {
  samples: SampleApp[];
  waking: boolean;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  if (samples.length === 0) {
    return (
      <div className="loading-line">
        <span className="spinner" />
        {waking ? "Waking up the server — the free host can take up to a minute…" : "Loading sample apps…"}
      </div>
    );
  }
  return (
    <>
      <p className="hint">Small, deliberately vulnerable apps with a verified ground truth. No upload needed.</p>
      <div className="sample-grid" role="radiogroup">
        {samples.map((s) => (
          <button
            key={s.id}
            type="button"
            role="radio"
            aria-checked={selected === s.id}
            className={`sample${selected === s.id ? " selected" : ""}`}
            onClick={() => onSelect(s.id)}
          >
            <span className="sample-head">
              <span className="sample-name">{s.name}</span>
              <span className="sample-radio" />
            </span>
            <span className="sample-desc">{s.description}</span>
          </button>
        ))}
      </div>
    </>
  );
}

function Dropzone({ onEntries, hasSelection }: { onEntries: (e: UploadEntry[]) => void; hasSelection: boolean }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  useEffect(() => {
    // `webkitdirectory` has no React prop / TS type, so it's set imperatively.
    inputRef.current?.setAttribute("webkitdirectory", "");
    inputRef.current?.setAttribute("directory", "");
  }, []);

  return (
    <div
      className={`dropzone${over ? " over" : ""}${hasSelection ? " compact" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={async (e) => {
        e.preventDefault();
        setOver(false);
        const dropped = await entriesFromDataTransfer(e.dataTransfer.items);
        if (dropped.length) onEntries(dropped);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        multiple
        hidden
        onChange={(e) => e.target.files?.length && onEntries(entriesFromFileList(e.target.files))}
      />
      <Icon name="upload" size={hasSelection ? 16 : 22} />
      <div className="dropzone-text">
        <strong>{hasSelection ? "Choose a different folder" : "Drop a project folder here"}</strong>
        {!hasSelection && <span>Python projects up to 5,000 lines. Files are checked in your browser before anything is sent.</span>}
      </div>
      <button type="button" className="btn" onClick={() => inputRef.current?.click()}>
        Browse…
      </button>
    </div>
  );
}

const REASON_ORDER: ExcludeReason[] = ["sensitive", "excluded-by-you", "dependency", "unsupported", "too-large"];

function PreflightReview({ report, redact, onRedactChange }: { report: PreflightReport; redact: boolean; onRedactChange: (v: boolean) => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const groups = REASON_ORDER.map((reason) => ({ reason, files: report.excluded.filter((f) => f.reason === reason) })).filter(
    (g) => g.files.length > 0,
  );
  const secretFiles = new Set(report.secrets.map((s) => s.path)).size;

  return (
    <div className="preflight">
      <div className="preflight-head">
        <div>
          <span className="preflight-title">
            <Icon name="folder" /> {report.folderName || "Selected files"}
          </span>
          <span className="preflight-sub">
            {report.totalFiles.toLocaleString()} files found · {report.pythonLines.toLocaleString()} lines of Python
          </span>
        </div>
        <div className="preflight-stat">
          <strong>{report.included.length}</strong>
          <span>will upload · {formatBytes(report.includedBytes)}</span>
        </div>
      </div>

      {report.blockers.map((b) => (
        <div key={b} className="notice notice-error">
          <Icon name="alert" /> {b}
        </div>
      ))}

      {report.secrets.length > 0 && (
        <div className="notice notice-warn">
          <Icon name="alert" />
          <div>
            <strong>
              {report.secrets.length} possible hardcoded secret{report.secrets.length === 1 ? "" : "s"} in {secretFiles} file
              {secretFiles === 1 ? "" : "s"}
            </strong>
            <ul className="secret-list">
              {report.secrets.slice(0, 5).map((s) => (
                <li key={`${s.path}:${s.line}:${s.kind}`}>
                  <code>
                    {s.path}:{s.line}
                  </code>{" "}
                  — {s.kind}
                </li>
              ))}
              {report.secrets.length > 5 && <li>…and {report.secrets.length - 5} more</li>}
            </ul>
            <label className="check">
              <input type="checkbox" checked={redact} onChange={(e) => onRedactChange(e.target.checked)} />
              Redact these values before uploading (line numbers are preserved)
            </label>
          </div>
        </div>
      )}

      <ul className="preflight-groups">
        <li>
          <button type="button" className="preflight-group" onClick={() => setOpen(open === "in" ? null : "in")}>
            <span className="dot dot-ok" />
            Will upload
            <span className="count">{report.included.length}</span>
            <Icon name={open === "in" ? "chevronDown" : "chevronRight"} className="muted" />
          </button>
          {open === "in" && (
            <ul className="file-list">
              {report.included.map((e) => (
                <li key={e.path}>
                  <code>{e.path.split("/").slice(1).join("/") || e.path}</code>
                </li>
              ))}
            </ul>
          )}
        </li>
        {groups.map((g) => (
          <li key={g.reason}>
            <button type="button" className="preflight-group" onClick={() => setOpen(open === g.reason ? null : g.reason)}>
              <span className={`dot ${g.reason === "sensitive" ? "dot-block" : "dot-skip"}`} />
              {REASON_LABEL[g.reason]}
              <span className="count">{g.files.length}</span>
              <Icon name={open === g.reason ? "chevronDown" : "chevronRight"} className="muted" />
            </button>
            {open === g.reason && (
              <ul className="file-list">
                {g.files.slice(0, 200).map((f) => (
                  <li key={f.path}>
                    <code>{f.path}</code>
                    <span>{f.detail}</span>
                  </li>
                ))}
                {g.files.length > 200 && <li className="muted">…and {g.files.length - 200} more</li>}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------

const SCANNERS: { id: ScannerId; name: string; desc: string; live: boolean }[] = [
  { id: "semgrep", name: "Semgrep", desc: "Pattern + taint rules, 30+ languages", live: true },
  { id: "bandit", name: "Bandit", desc: "Python security linter", live: false },
  { id: "codeql", name: "CodeQL", desc: "Dataflow queries", live: false },
];

const RULESETS = [
  { id: "auto", label: "Auto (recommended)", live: true },
  { id: "p/python", label: "p/python", live: false },
  { id: "p/owasp-top-ten", label: "p/owasp-top-ten", live: false },
  { id: "p/security-audit", label: "p/security-audit", live: false },
  { id: "p/secrets", label: "p/secrets", live: false },
];

function ScanSettings({
  options,
  onChange,
  excludeText,
  onExcludeChange,
  showExcludes,
  onOpenRoadmap,
}: {
  options: ScanOptions;
  onChange: (o: ScanOptions) => void;
  excludeText: string;
  onExcludeChange: (t: string) => void;
  showExcludes: boolean;
  onOpenRoadmap: () => void;
}) {
  return (
    <Card title="2 · Scan settings" className="settings">
      <fieldset>
        <legend>Scanners</legend>
        {SCANNERS.map((s) => (
          <div key={s.id} className="option-row">
            <label className={`option${s.live ? "" : " disabled"}`}>
              <input type="checkbox" checked={options.scanners.includes(s.id)} disabled={!s.live} readOnly />
              <span className="option-text">
                <span className="option-name">{s.name}</span>
                <span className="option-desc">{s.desc}</span>
              </span>
            </label>
            {!s.live && <StatusTag status="planned" onClick={onOpenRoadmap} />}
          </div>
        ))}
      </fieldset>

      <fieldset>
        <legend>Semgrep ruleset</legend>
        <select
          className="select"
          aria-label="Semgrep ruleset"
          value={options.semgrep_ruleset}
          onChange={(e) => onChange({ ...options, semgrep_ruleset: e.target.value })}
        >
          {RULESETS.map((r) => (
            <option key={r.id} value={r.id} disabled={!r.live}>
              {r.label}
              {r.live ? "" : " — planned"}
            </option>
          ))}
        </select>
      </fieldset>

      <fieldset>
        <legend>Validation stages</legend>
        <label className="option">
          <input type="checkbox" checked disabled />
          <span className="option-text">
            <span className="option-name">Deduplicate</span>
            <span className="option-desc">One finding per location</span>
          </span>
        </label>
        <label className="option">
          {/* Always runs server-side today, so it isn't presented as optional. */}
          <input type="checkbox" checked disabled />
          <span className="option-text">
            <span className="option-name">Reachability</span>
            <span className="option-desc">Call graph from entry points</span>
          </span>
        </label>
        <div className="option-row">
          <label className="option disabled">
            <input type="checkbox" checked={options.analyses.taint} disabled readOnly />
            <span className="option-text">
              <span className="option-name">Taint signal</span>
              <span className="option-desc">Does input reach the sink?</span>
            </span>
          </label>
          <StatusTag status="planned" onClick={onOpenRoadmap} />
        </div>
        <div className="option-row">
          <label className="option disabled">
            <input type="checkbox" checked={options.analyses.exploitability_static} disabled readOnly />
            <span className="option-text">
              <span className="option-name">Exploitability agent</span>
              <span className="option-desc">Tier A static reasoning</span>
            </span>
          </label>
          <StatusTag status="planned" onClick={onOpenRoadmap} />
        </div>
      </fieldset>

      {showExcludes && (
        <fieldset>
          <legend>Exclude paths</legend>
          <textarea
            className="textarea"
            aria-label="Exclude paths (one glob per line)"
            rows={3}
            spellCheck={false}
            placeholder={"tests/**\n**/migrations/**"}
            value={excludeText}
            onChange={(e) => onExcludeChange(e.target.value)}
          />
          <span className="field-hint">One glob per line. Applied before upload.</span>
        </fieldset>
      )}
    </Card>
  );
}
