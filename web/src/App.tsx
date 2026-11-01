import { useState } from "react";
import { datasetUrl, runScan } from "./api";
import { CAShareChart, IssuanceChart, LifetimeChart } from "./components/Charts";
import { DomainsList } from "./components/DomainsList";
import { Findings } from "./components/Findings";
import { ScanForm } from "./components/ScanForm";
import { StatCards } from "./components/StatCards";
import type { Results } from "./types";

type Phase = "idle" | "running" | "done" | "error";

export function App() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [statusText, setStatusText] = useState("");
  const [error, setError] = useState("");
  const [results, setResults] = useState<Results | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  async function handleScan(target: string, anonymize: boolean) {
    setPhase("running");
    setError("");
    setResults(null);
    setStatusText(`Querying crt.sh for ${target}…`);
    try {
      const { job, results } = await runScan(target, { anonymize }, (j) =>
        setStatusText(`Scan ${j.status}…`),
      );
      setJobId(job.id);
      setResults(results);
      setPhase("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase("error");
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>ct-lens</h1>
          <p className="tagline">
            The HTTPS certificate landscape of a whole TLD — from public Certificate
            Transparency logs. No target server is ever contacted.
          </p>
        </div>
      </header>

      <ScanForm disabled={phase === "running"} onScan={handleScan} />

      {phase === "running" && <p className="status">{statusText}</p>}
      {phase === "error" && <p className="status error">⚠ {error}</p>}

      {phase === "idle" && (
        <p className="muted hint">
          Enter a TLD (e.g. <code>.lk</code>), a domain, or a crt.sh pattern, then press
          Analyse.
        </p>
      )}

      {results && (
        <main className="results">
          <div className="results-head">
            <h2>
              <code>{results.pattern}</code>
            </h2>
            {jobId && (
              <div className="downloads">
                <a href={datasetUrl(jobId, "csv")}>Download CSV</a>
                <a href={datasetUrl(jobId, "json")}>Download JSON</a>
              </div>
            )}
          </div>

          <StatCards results={results} />

          <div className="chart-grid">
            <CAShareChart results={results} />
            <LifetimeChart results={results} />
            <IssuanceChart results={results} />
          </div>

          <Findings findings={results.findings} />

          <DomainsList domains={results.domains} />
        </main>
      )}

      <footer className="app-footer">
        <span>
          Built with ct-lens · aggregate / anonymised by default · defensive, public-data only
        </span>
      </footer>
    </div>
  );
}
