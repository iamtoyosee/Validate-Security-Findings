import type { ScanResponse } from "../types";

type Tab = "findings" | "reachability" | "exploitability";

function FunnelStep({
  value,
  label,
  stage,
  pending,
  urgent,
  onClick,
}: {
  value: number | null;
  label: string;
  stage: "raw" | "distinct" | "reachable" | "exploitable";
  pending?: boolean;
  urgent?: boolean;
  onClick: () => void;
}) {
  const classes = [
    "funnel-step",
    `funnel-step-${stage}`,
    pending && "funnel-step-pending",
    urgent && "funnel-step-urgent",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button type="button" className={classes} onClick={onClick}>
      <span className="funnel-circle">{pending ? "—" : value}</span>
      <span className="funnel-step-label">{label}</span>
    </button>
  );
}

function FunnelLine({ label }: { label: string }) {
  return (
    <div className="funnel-line">
      <span className="funnel-line-label">{label}</span>
    </div>
  );
}

export function ScanFunnel({ result, onNavigate }: { result: ScanResponse; onNavigate: (tab: Tab) => void }) {
  const reachableCount = result.reachability.filter((v) => v.status === "reachable").length;

  return (
    <div className="funnel" aria-label="Scan pipeline: raw results narrowing down to what needs review">
      <FunnelStep
        value={result.raw_result_count}
        label="Raw results"
        stage="raw"
        onClick={() => onNavigate("findings")}
      />
      <FunnelLine label="Deduplication" />
      <FunnelStep
        value={result.findings.length}
        label="Distinct findings"
        stage="distinct"
        onClick={() => onNavigate("findings")}
      />
      <FunnelLine label="Reachability" />
      <FunnelStep
        value={reachableCount}
        label="Reachable"
        stage="reachable"
        onClick={() => onNavigate("reachability")}
      />
      <FunnelLine label="Exploitability" />
      {/* Phase 4/5 isn't built yet, so this is always pending/null for now. Once real
          exploitability counts exist, pass that value here and set urgent={count > 0} -
          the red, pulsing "pay attention" treatment is already built, just unused today. */}
      <FunnelStep
        value={null}
        label="Exploitable"
        stage="exploitable"
        pending
        onClick={() => onNavigate("exploitability")}
      />
    </div>
  );
}
