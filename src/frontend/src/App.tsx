import { useCallback, useMemo, useRef, useState } from "react";
import "./App.css";
import { scanCodebase, scanSample } from "./api";
import { ExploitabilityView } from "./components/ExploitabilityView";
import { FindingDrawer } from "./components/FindingDrawer";
import { FindingsTable } from "./components/FindingsTable";
import type { ScanRequest } from "./components/NewScan";
import { NewScan } from "./components/NewScan";
import { OverviewView } from "./components/OverviewView";
import { HistoryPanel, RoadmapPanel, TopBar } from "./components/Panels";
import { ReachabilityView } from "./components/ReachabilityView";
import type { ResultsTab } from "./components/ResultsHeader";
import { ResultsHeader } from "./components/ResultsHeader";
import { ScanProgress } from "./components/ScanProgress";
import { Icon } from "./components/ui";
import type { ExportFormat } from "./lib/exporters";
import { exportScan } from "./lib/exporters";
import type { Filters } from "./lib/filters";
import { EMPTY_FILTERS, applyFilters } from "./lib/filters";
import { buildPreviewExploitability } from "./lib/previewData";
import type { HistoryEntry, ScanTarget, TriageState } from "./lib/storage";
import { clearHistory, diffScans, loadHistory, previousScanOf, saveToHistory, useTriage } from "./lib/storage";
import { prepareUpload } from "./lib/uploadSafety";
import { buildValidated } from "./lib/validated";
import type { ScanOptions, ScanResponse } from "./types";

const DEFAULT_OPTIONS: ScanOptions = {
  scanners: ["semgrep"],
  semgrep_ruleset: "auto",
  analyses: { reachability: true, taint: false, exploitability_static: false, exploitability_dynamic: false },
  exclude_globs: [],
};

type View = "new" | "scanning" | "results";

/** Timing + id for a history entry, kept outside the component (impure by nature). */
function startClock() {
  const startedAt = new Date().toISOString();
  const t0 = performance.now();
  return {
    finish: () => ({
      id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
      startedAt,
      durationMs: Math.round(performance.now() - t0),
    }),
  };
}

function App() {
  const [view, setView] = useState<View>("new");
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [current, setCurrent] = useState<HistoryEntry | null>(null);
  const [scanningLabel, setScanningLabel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const [tab, setTab] = useState<ResultsTab>("overview");
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [previewMode, setPreviewMode] = useState(false);
  const [panel, setPanel] = useState<"roadmap" | "history" | null>(null);

  const { decisions, setDecision, stateOf } = useTriage(current?.target.key ?? "none");
  const abortRef = useRef<AbortController | null>(null);

  // ---- Scanning ----------------------------------------------------------

  const runScan = async (target: ScanTarget, run: (signal: AbortSignal) => Promise<ScanResponse>) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setScanningLabel(target.label);
    setError(null);
    setView("scanning");
    const clock = startClock();
    try {
      const result = await run(controller.signal);
      // A newer scan started, or the user navigated away - drop this result.
      if (abortRef.current !== controller) return;
      const entry: HistoryEntry = { ...clock.finish(), target, options, result };
      setHistory(saveToHistory(entry));
      openResults(entry);
    } catch (err) {
      if (controller.signal.aborted || abortRef.current !== controller) return;
      setError(err instanceof Error ? err.message : "Unexpected error during scan.");
      setView("new");
    }
  };

  const handleScan = async (req: ScanRequest) => {
    if (req.kind === "sample") {
      const { sample } = req;
      await runScan({ kind: "sample", key: `sample:${sample.id}`, label: sample.name }, (signal) =>
        scanSample(sample.id, options, signal),
      );
    } else {
      const label = req.report.folderName || "Uploaded files";
      await runScan({ kind: "upload", key: `upload:${label}`, label }, async (signal) =>
        scanCodebase(await prepareUpload(req.report, req.redact), options, signal),
      );
    }
  };

  const rescan = () => {
    if (!current || current.target.kind !== "sample") return;
    const id = current.target.key.replace(/^sample:/, "");
    runScan(current.target, (signal) => scanSample(id, options, signal));
  };

  const openResults = (entry: HistoryEntry) => {
    setCurrent(entry);
    setTab("overview");
    setFilters(EMPTY_FILTERS);
    setSelectedId(null);
    setPreviewMode(false);
    setPanel(null);
    setView("results");
  };

  // ---- Derived results ---------------------------------------------------

  const hasRealVerdicts = !!current?.result.exploitability?.length;
  const effectiveResult = useMemo(() => {
    if (!current) return null;
    if (previewMode && !hasRealVerdicts) {
      return { ...current.result, exploitability: buildPreviewExploitability(current.result) };
    }
    return current.result;
  }, [current, previewMode, hasRealVerdicts]);

  const rows = useMemo(() => (effectiveResult ? buildValidated(effectiveResult) : []), [effectiveResult]);
  const diff = useMemo(
    () => (current ? diffScans(current.result, previousScanOf(history, current)) : undefined),
    [current, history],
  );
  const showExploit = hasRealVerdicts || previewMode;

  // Drawer prev/next walks whatever list the user is looking at.
  const navList = useMemo(
    () => (tab === "findings" ? applyFilters(rows, filters, stateOf, diff?.newIds) : rows),
    [tab, rows, filters, stateOf, diff],
  );
  const navIndex = navList.findIndex((r) => r.id === selectedId);
  const selectedRow = rows.find((r) => r.id === selectedId);
  const step = useCallback(
    (delta: number) => {
      const next = navList[navIndex + delta];
      if (next) setSelectedId(next.id);
    },
    [navList, navIndex],
  );

  const goFiltered = (f: Filters) => {
    setFilters(f);
    setTab("findings");
  };

  // Always export the real results - never the example exploitability verdicts.
  const handleExport = (format: ExportFormat) => {
    if (current) exportScan(format, current, buildValidated(current.result), decisions);
  };

  const goHome = () => {
    if (view === "scanning") abortRef.current?.abort();
    abortRef.current = null;
    setView("new");
  };

  const bulkTriage = (ids: string[], state: TriageState) => ids.forEach((id) => setDecision(id, { state }));

  // ---- Render ------------------------------------------------------------

  return (
    <div className="shell">
      <TopBar
        onHome={goHome}
        onHistory={() => setPanel("history")}
        onRoadmap={() => setPanel("roadmap")}
        showNewScan={view === "results"}
      />

      <main className="page">
        {view === "new" && (
          <>
            {error && (
              <div className="notice notice-error page-notice" role="alert">
                <Icon name="alert" />
                <div>
                  <strong>Scan failed.</strong> {error}
                </div>
                <button type="button" className="icon-btn" onClick={() => setError(null)} aria-label="Dismiss">
                  <Icon name="x" />
                </button>
              </div>
            )}
            <NewScan
              options={options}
              onOptionsChange={setOptions}
              onScan={handleScan}
              history={history}
              onOpenHistory={openResults}
              onOpenRoadmap={() => setPanel("roadmap")}
            />
          </>
        )}

        {view === "scanning" && <ScanProgress target={scanningLabel} onCancel={goHome} />}

        {view === "results" && current && (
          <>
            <ResultsHeader
              scan={current}
              rows={rows}
              diff={diff}
              hasExploitability={showExploit}
              previewMode={previewMode && !hasRealVerdicts}
              tab={tab}
              onTab={setTab}
              onExport={handleExport}
              onRescan={rescan}
              onHidePreview={() => setPreviewMode(false)}
            />
            <div className="tab-body">
              {tab === "overview" && (
                <OverviewView rows={rows} stateOf={stateOf} diff={diff} onFilter={goFiltered} onOpen={setSelectedId} />
              )}
              {tab === "findings" && (
                <FindingsTable
                  rows={rows}
                  filters={filters}
                  onFilters={setFilters}
                  stateOf={stateOf}
                  decisions={decisions}
                  onBulkTriage={bulkTriage}
                  onOpen={setSelectedId}
                  selectedId={selectedId}
                  newIds={diff?.newIds}
                  showExploit={showExploit}
                />
              )}
              {tab === "reachability" && <ReachabilityView rows={rows} onOpen={setSelectedId} />}
              {tab === "exploitability" && (
                <ExploitabilityView
                  rows={rows}
                  hasRealVerdicts={hasRealVerdicts}
                  previewMode={previewMode}
                  onPreviewMode={setPreviewMode}
                  target={current.target}
                  onOpen={setSelectedId}
                  onOpenRoadmap={() => setPanel("roadmap")}
                />
              )}
            </div>
          </>
        )}
      </main>

      {selectedRow && (
        <FindingDrawer
          row={selectedRow}
          index={navIndex === -1 ? 0 : navIndex}
          total={navIndex === -1 ? 1 : navList.length}
          onPrev={() => step(-1)}
          onNext={() => step(1)}
          onClose={() => setSelectedId(null)}
          decision={decisions[selectedRow.id]}
          onTriage={(patch) => setDecision(selectedRow.id, patch)}
          previewMode={previewMode && !hasRealVerdicts}
          onOpenRoadmap={() => setPanel("roadmap")}
        />
      )}

      {panel === "roadmap" && <RoadmapPanel onClose={() => setPanel(null)} />}
      {panel === "history" && (
        <HistoryPanel
          history={history}
          currentId={current?.id}
          onOpen={openResults}
          onClear={() => {
            clearHistory();
            setHistory([]);
          }}
          onClose={() => setPanel(null)}
        />
      )}
    </div>
  );
}

export default App;
