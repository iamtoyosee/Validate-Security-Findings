import { useEffect } from "react";
import type { ReactNode } from "react";
import type { Capability } from "../lib/capabilities";
import { CAPABILITIES } from "../lib/capabilities";
import { timeAgo } from "../lib/format";
import type { HistoryEntry } from "../lib/storage";
import { Icon, StatusTag } from "./ui";

function SidePanel({ title, subtitle, onClose, children }: { title: string; subtitle?: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer drawer-narrow" role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-head">
          <div>
            <h2 className="panel-title">{title}</h2>
            {subtitle && <p className="muted small panel-sub">{subtitle}</p>}
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="x" />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

const AREAS: Capability["area"][] = ["Ingest", "Analysis", "Triage", "Reporting"];

export function RoadmapPanel({ onClose }: { onClose: () => void }) {
  const counts = {
    live: CAPABILITIES.filter((c) => c.status === "live").length,
    client: CAPABILITIES.filter((c) => c.status === "client").length,
    planned: CAPABILITIES.filter((c) => c.status === "planned").length,
  };
  return (
    <SidePanel title="Feature status" subtitle="What runs on the server today, what runs in your browser, and what's designed but waiting on the backend." onClose={onClose}>
      <div className="roadmap-legend">
        <span>
          <StatusTag status="live" /> {counts.live} server
        </span>
        <span>
          <StatusTag status="client" /> {counts.client} browser
        </span>
        <span>
          <StatusTag status="planned" /> {counts.planned} planned
        </span>
      </div>
      {AREAS.map((area) => (
        <section key={area} className="roadmap-area">
          <h3>{area}</h3>
          <ul className="roadmap">
            {CAPABILITIES.filter((c) => c.area === area).map((c) => (
              <li key={c.id} className="roadmap-item">
                <div className="roadmap-head">
                  <strong>{c.name}</strong>
                  {c.phase && <span className="muted small">Phase {c.phase}</span>}
                  <StatusTag status={c.status} />
                </div>
                <p>{c.summary}</p>
                {c.backendWork && (
                  <p className="roadmap-work">
                    <span>Backend:</span> {c.backendWork}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </section>
      ))}
      <p className="muted small">
        Full contract (field shapes, endpoints): <code>docs/frontend-feature-roadmap.md</code>
      </p>
    </SidePanel>
  );
}

export function HistoryPanel({
  history,
  currentId,
  onOpen,
  onClear,
  onClose,
}: {
  history: HistoryEntry[];
  currentId?: string;
  onOpen: (h: HistoryEntry) => void;
  onClear: () => void;
  onClose: () => void;
}) {
  return (
    <SidePanel title="Scan history" subtitle="The last 10 scans, kept in this browser." onClose={onClose}>
      {history.length === 0 ? (
        <p className="muted">No scans yet.</p>
      ) : (
        <>
          <ul className="history">
            {history.map((h) => {
              const reachable = h.result.reachability.filter((r) => r.status === "reachable").length;
              return (
                <li key={h.id}>
                  <button type="button" className={`history-row${h.id === currentId ? " current" : ""}`} onClick={() => onOpen(h)}>
                    <Icon name={h.target.kind === "sample" ? "box" : "folder"} />
                    <span className="history-main">
                      <strong>{h.target.label}</strong>
                      <span className="muted small">
                        {h.result.raw_result_count} raw → {h.result.findings.length} distinct → {reachable} reachable
                      </span>
                    </span>
                    <span className="muted small">{timeAgo(h.startedAt)}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <button type="button" className="link danger" onClick={onClear}>
            Clear history
          </button>
        </>
      )}
    </SidePanel>
  );
}

export function TopBar({
  onHome,
  onHistory,
  onRoadmap,
  showNewScan,
}: {
  onHome: () => void;
  onHistory: () => void;
  onRoadmap: () => void;
  showNewScan: boolean;
}) {
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <button type="button" className="brand" onClick={onHome}>
          <span className="brand-mark">
            <Icon name="shieldCheck" size={16} />
          </span>
          <span className="brand-name">Validate</span>
          <span className="brand-sub">security findings</span>
        </button>
        <nav className="topnav">
          {showNewScan && (
            <button type="button" className="btn btn-sm" onClick={onHome}>
              <Icon name="play" size={12} /> New scan
            </button>
          )}
          <button type="button" className="nav-link" onClick={onHistory}>
            <Icon name="history" size={14} /> History
          </button>
          <button type="button" className="nav-link" onClick={onRoadmap}>
            <Icon name="map" size={14} /> Roadmap
          </button>
          <a className="nav-link" href="https://github.com/iamtoyosee/Validate-Security-Findings" target="_blank" rel="noreferrer" aria-label="GitHub repository">
            <Icon name="github" size={16} />
          </a>
        </nav>
      </div>
    </header>
  );
}
