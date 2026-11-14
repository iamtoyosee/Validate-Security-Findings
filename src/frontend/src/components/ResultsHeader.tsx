import { useEffect, useRef, useState } from "react";
import type { ExportFormat } from "../lib/exporters";
import { EXPORT_FORMATS } from "../lib/exporters";
import { timeAgo } from "../lib/format";
import type { HistoryEntry, ScanDiff } from "../lib/storage";
import type { ValidatedFinding } from "../lib/validated";
import { needsAttention } from "../lib/validated";
import { Icon } from "./ui";

export type ResultsTab = "overview" | "findings" | "reachability" | "exploitability";

interface Props {
  scan: HistoryEntry;
  rows: ValidatedFinding[];
  diff?: ScanDiff;
  hasExploitability: boolean;
  previewMode: boolean;
  tab: ResultsTab;
  onTab: (t: ResultsTab) => void;
  onExport: (f: ExportFormat) => void;
  onRescan: () => void;
  onHidePreview: () => void;
}

export function ResultsHeader({ scan, rows, diff, hasExploitability, previewMode, tab, onTab, onExport, onRescan, onHidePreview }: Props) {
  const raw = scan.result.raw_result_count;
  const distinct = rows.length;
  const reachable = rows.filter((r) => r.reachability?.status === "reachable").length;
  const exploitable = rows.filter((r) => r.exploit === "exploitable").length;
  const attention = rows.filter(needsAttention).length;
  const filteredPct = raw === 0 ? 0 : Math.round(((raw - attention) / raw) * 100);

  return (
    <div className="results-head">
      <div className="results-title-row">
        <div>
          <div className="eyebrow">
            <Icon name={scan.target.kind === "sample" ? "box" : "folder"} size={13} />
            {scan.target.kind === "sample" ? "Sample app" : "Uploaded folder"}
            <span className="sep">·</span>
            {timeAgo(scan.startedAt)}
            <span className="sep">·</span>
            {(scan.durationMs / 1000).toFixed(1)}s
            {diff && (
              <>
                <span className="sep">·</span>
                <span className="diff">
                  <span className="diff-new">+{diff.newIds.size} new</span>
                  <span className="diff-resolved">−{diff.resolvedCount} resolved</span>
                  since {timeAgo(diff.previousAt)}
                </span>
              </>
            )}
          </div>
          <h1>{scan.target.label}</h1>
        </div>
        <div className="results-actions">
          {scan.target.kind === "sample" && (
            <button type="button" className="btn" onClick={onRescan}>
              <Icon name="history" size={14} /> Re-scan
            </button>
          )}
          <ExportMenu onExport={onExport} />
        </div>
      </div>

      {previewMode && (
        <div className="notice notice-example">
          <Icon name="alert" />
          <div>
            <strong>Example exploitability data is on.</strong> Verdicts and the priorities they affect are illustrative
            only, across every tab. Exports always use the real results.
          </div>
          <button type="button" className="btn btn-sm" onClick={onHidePreview}>
            Hide examples
          </button>
        </div>
      )}

      <div className="funnel" aria-label="Pipeline: raw results narrowed to what needs attention">
        <FunnelStep value={raw} label="Raw results" onClick={() => onTab("findings")} />
        <FunnelArrow label="dedupe" />
        <FunnelStep value={distinct} label="Distinct findings" onClick={() => onTab("findings")} />
        <FunnelArrow label="reachability" />
        <FunnelStep value={reachable} label="Reachable" tone="reach" onClick={() => onTab("reachability")} />
        <FunnelArrow label="exploitability" />
        <FunnelStep
          value={hasExploitability ? exploitable : null}
          label={previewMode ? "Exploitable · example" : "Exploitable"}
          tone="exploit"
          onClick={() => onTab("exploitability")}
        />
        <div className="funnel-summary">
          <strong>{filteredPct}%</strong>
          <span>of raw output filtered as noise</span>
        </div>
      </div>

      <nav className="tabs" role="tablist">
        {(
          [
            ["overview", "Overview", null],
            ["findings", "Findings", distinct],
            ["reachability", "Reachability", reachable],
            ["exploitability", "Exploitability", hasExploitability ? exploitable : null],
          ] as const
        ).map(([id, label, count]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} className={tab === id ? "active" : ""} onClick={() => onTab(id)}>
            {label}
            {count !== null && <span className="tab-count">{count}</span>}
          </button>
        ))}
      </nav>
    </div>
  );
}

function FunnelStep({ value, label, tone, onClick }: { value: number | null; label: string; tone?: "reach" | "exploit"; onClick: () => void }) {
  const urgent = tone === "exploit" && value !== null && value > 0;
  return (
    <button type="button" className={`funnel-step${tone ? ` tone-${tone}` : ""}${urgent ? " urgent" : ""}`} onClick={onClick}>
      <span className="funnel-value">{value === null ? "—" : value}</span>
      <span className="funnel-label">{label}</span>
    </button>
  );
}

function FunnelArrow({ label }: { label: string }) {
  return (
    <span className="funnel-arrow" aria-hidden="true">
      <Icon name="chevronRight" size={14} />
      <span>{label}</span>
    </span>
  );
}

function ExportMenu({ onExport }: { onExport: (f: ExportFormat) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn btn-primary" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="download" size={14} /> Export
        <Icon name="chevronDown" size={12} />
      </button>
      {open && (
        <div className="menu-pop" role="menu">
          {EXPORT_FORMATS.map((f) => (
            <button
              key={f.id}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                onExport(f.id);
                setOpen(false);
              }}
            >
              <span className="menu-item-label">{f.label}</span>
              <span className="menu-item-hint">{f.hint}</span>
            </button>
          ))}
          <p className="menu-foot">Exports include your triage decisions.</p>
        </div>
      )}
    </div>
  );
}
