import { useState } from "react";
import "./App.css";
import { scanCodebase } from "./api";
import { FindingsView } from "./components/FindingsView";
import { Placeholder } from "./components/Placeholder";
import { UploadPanel } from "./components/UploadPanel";
import type { ScanResponse } from "./types";

type Tab = "findings" | "reachability" | "exploitability";
type ScanStatus = "idle" | "loading" | "success" | "error";

function App() {
  const [tab, setTab] = useState<Tab>("findings");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (files: File[]) => {
    setStatus("loading");
    setError(null);
    try {
      const response = await scanCodebase(files);
      setResult(response);
      setStatus("success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unexpected error during scan.");
      setStatus("error");
    }
  };

  return (
    <div className="app">
      <header>
        <h1>Agentic Vulnerability Validation</h1>
        <p className="subtitle">Upload a codebase to scan it for findings.</p>
      </header>

      <UploadPanel onScan={handleScan} loading={status === "loading"} />

      {status === "error" && error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}

      <nav className="tabs">
        <button type="button" className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>
          Findings
        </button>
        <button
          type="button"
          className={tab === "reachability" ? "active" : ""}
          onClick={() => setTab("reachability")}
        >
          Reachability Analysis
        </button>
        <button
          type="button"
          className={tab === "exploitability" ? "active" : ""}
          onClick={() => setTab("exploitability")}
        >
          Exploitability Analysis
        </button>
      </nav>

      <main>
        {tab === "findings" &&
          (result ? (
            <FindingsView result={result} />
          ) : (
            <p className="empty-state">
              {status === "loading" ? "Scanning…" : "Scan a folder to see findings here."}
            </p>
          ))}
        {tab === "reachability" && <Placeholder label="Reachability Analysis" />}
        {tab === "exploitability" && <Placeholder label="Exploitability Analysis" />}
      </main>
    </div>
  );
}

export default App;
