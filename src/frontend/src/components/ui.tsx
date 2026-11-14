import type { ReactNode } from "react";
import type { CapabilityStatus } from "../lib/capabilities";
import { STATUS_LABEL } from "../lib/capabilities";
import type { TriageState } from "../lib/storage";
import { TRIAGE_LABEL } from "../lib/storage";
import type { Exploitability, PriorityTier, Severity } from "../lib/validated";
import { EXPLOITABILITY_LABEL, PRIORITY_HINT, SEVERITY_LABEL } from "../lib/validated";
import type { Confidence, ReachabilityStatus } from "../types";

// ---------------------------------------------------------------------------
// Icons - a small inline set (stroke-based, 16px grid) so there's no icon dependency.
// ---------------------------------------------------------------------------

const PATHS: Record<string, ReactNode> = {
  shield: <path d="M8 1.5 2.5 3.5v4c0 3.3 2.3 5.9 5.5 7 3.2-1.1 5.5-3.7 5.5-7v-4L8 1.5Z" />,
  shieldCheck: (
    <>
      <path d="M8 1.5 2.5 3.5v4c0 3.3 2.3 5.9 5.5 7 3.2-1.1 5.5-3.7 5.5-7v-4L8 1.5Z" />
      <path d="m5.5 8 1.8 1.8L10.8 6.3" />
    </>
  ),
  upload: <path d="M8 10.5V2.5M4.5 6 8 2.5 11.5 6M2.5 10.5v2a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-2" />,
  folder: <path d="M1.5 4a1 1 0 0 1 1-1h3.6l1.5 1.5h5.9a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1h-11a1 1 0 0 1-1-1V4Z" />,
  box: <path d="m8 1.5 5.5 3v7L8 14.5l-5.5-3v-7L8 1.5Zm0 6.5 5.5-3.5M8 8 2.5 4.5M8 8v6.5" />,
  file: <path d="M4 1.5h5L12.5 5v9a.5.5 0 0 1-.5.5H4a.5.5 0 0 1-.5-.5V2a.5.5 0 0 1 .5-.5ZM9 1.5V5h3.5" />,
  history: <path d="M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v2.5H5M8 5v3l2 1.5" />,
  map: <path d="M1.5 3.5 5.5 2l5 2 4-1.5v10l-4 1.5-5-2-4 1.5v-10ZM5.5 2v10M10.5 4v10" />,
  x: <path d="m4 4 8 8M12 4l-8 8" />,
  chevronRight: <path d="m6 3.5 4.5 4.5L6 12.5" />,
  chevronLeft: <path d="M10 3.5 5.5 8l4.5 4.5" />,
  chevronDown: <path d="m3.5 6 4.5 4.5L12.5 6" />,
  download: <path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M2.5 13.5h11" />,
  check: <path d="m3 8.5 3 3 7-7" />,
  alert: <path d="M8 1.8 15 14H1L8 1.8ZM8 6.5v3.2M8 11.6v.4" />,
  lock: <path d="M4 7V5a4 4 0 0 1 8 0v2M3 7h10v7H3V7Z" />,
  external: <path d="M9 2.5h4.5V7M13.5 2.5 7.5 8.5M11.5 9v4.5h-9v-9H7" />,
  search: <path d="M7 12A5 5 0 1 0 7 2a5 5 0 0 0 0 10ZM10.6 10.6l3.4 3.4" />,
  code: <path d="M5.5 4 1.5 8l4 4M10.5 4l4 4-4 4" />,
  agent: <path d="M8 1.5v2M3.5 5.5h9a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-6a1 1 0 0 1 1-1ZM6 9v.5M10 9v.5M.5 9h2M13.5 9h2" />,
  flask: <path d="M6 1.5h4M6.5 1.5v4.5L2.6 12.8a1 1 0 0 0 .9 1.7h9a1 1 0 0 0 .9-1.7L9.5 6V1.5M4.3 10h7.4" />,
  route: <path d="M3.5 13.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3ZM12.5 5.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3ZM3.5 10.5V7a3 3 0 0 1 3-3h4.5M12.5 5.5V9a3 3 0 0 1-3 3H5" />,
  play: <path d="M4.5 2.5v11l9-5.5-9-5.5Z" />,
  github: (
    <path d="M8 1.5a6.5 6.5 0 0 0-2 12.7c.3 0 .4-.2.4-.4v-1.3c-1.8.4-2.2-.8-2.2-.8-.3-.8-.7-1-.7-1-.6-.4 0-.4 0-.4.6 0 1 .7 1 .7.6 1 1.6.7 2 .5 0-.4.2-.7.4-.9-1.4-.2-3-.7-3-3.2 0-.7.3-1.3.7-1.7-.1-.2-.3-.8 0-1.7 0 0 .6-.2 1.8.7a6 6 0 0 1 3.2 0c1.2-.9 1.8-.7 1.8-.7.3.9.1 1.5 0 1.7.4.4.7 1 .7 1.7 0 2.5-1.6 3-3 3.2.2.2.4.6.4 1.2v1.8c0 .2.1.4.5.4A6.5 6.5 0 0 0 8 1.5Z" />
  ),
  eyeOff: <path d="M2 2l12 12M6.6 6.6a2 2 0 0 0 2.8 2.8M4.2 4.2C2.6 5.3 1.5 8 1.5 8s2.4 4.5 6.5 4.5c1.3 0 2.4-.4 3.3-1M7 3.6c.3 0 .6-.1 1-.1 4.1 0 6.5 4.5 6.5 4.5s-.5 1-1.5 2.1" />,
  sliders: <path d="M2.5 4.5h7M12.5 4.5h1M2.5 11.5h1M6.5 11.5h7M11 3v3M5 10v3" />,
};

export function Icon({ name, size = 16, className }: { name: keyof typeof PATHS; size?: number; className?: string }) {
  const filled = name === "github";
  return (
    <svg
      className={`icon${className ? ` ${className}` : ""}`}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill={filled ? "currentColor" : "none"}
      stroke={filled ? "none" : "currentColor"}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Badges - soft tinted pills. Color is never the only signal: every badge has a label.
// ---------------------------------------------------------------------------

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`pill pill-sev-${severity}`}><span className="pill-dot" />{SEVERITY_LABEL[severity]}</span>;
}

const REACH_LABEL: Record<ReachabilityStatus, string> = {
  reachable: "Reachable",
  unreachable: "Unreachable",
  unknown: "Unknown",
};

export function ReachBadge({ status, confidence }: { status?: ReachabilityStatus; confidence?: Confidence }) {
  if (!status) return <span className="pill pill-muted">Not analyzed</span>;
  return (
    <span className={`pill pill-reach-${status}`} title={confidence ? `${confidence} confidence` : undefined}>
      <span className="pill-dot" />
      {REACH_LABEL[status]}
    </span>
  );
}

export function ExploitBadge({ status }: { status: Exploitability }) {
  return (
    <span className={`pill pill-exploit-${status}`}>
      {status !== "not_analyzed" && <span className="pill-dot" />}
      {EXPLOITABILITY_LABEL[status]}
    </span>
  );
}

export function PriorityBadge({ tier, showHint }: { tier: PriorityTier; showHint?: boolean }) {
  return (
    <span className={`priority priority-${tier}`} title={PRIORITY_HINT[tier]}>
      {tier}
      {showHint && <span className="priority-hint">{PRIORITY_HINT[tier]}</span>}
    </span>
  );
}

export function TriageBadge({ state }: { state: TriageState }) {
  return <span className={`triage triage-${state}`}>{TRIAGE_LABEL[state]}</span>;
}

export function ConfidenceMeter({ confidence }: { confidence: Confidence }) {
  const bars = confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
  return (
    <span className="confidence" title={`${confidence} confidence`}>
      {[1, 2, 3].map((i) => (
        <span key={i} className={`confidence-bar${i <= bars ? " on" : ""}`} />
      ))}
      <span className="confidence-label">{confidence}</span>
    </span>
  );
}

/** Marks anything that isn't backed by the server yet. Click opens the roadmap. */
export function StatusTag({ status, onClick }: { status: CapabilityStatus; onClick?: () => void }) {
  const content = (
    <>
      {status === "client" && <Icon name="lock" size={11} />}
      {STATUS_LABEL[status]}
    </>
  );
  return onClick ? (
    <button type="button" className={`status-tag status-tag-${status}`} onClick={onClick}>
      {content}
    </button>
  ) : (
    <span className={`status-tag status-tag-${status}`}>{content}</span>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  action,
}: {
  icon: keyof typeof PATHS;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={20} />
      </span>
      <h3>{title}</h3>
      {children && <div className="empty-body">{children}</div>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

export function Card({ title, aside, children, className }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card${className ? ` ${className}` : ""}`}>
      {(title || aside) && (
        <header className="card-head">
          {title && <h3 className="card-title">{title}</h3>}
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}
