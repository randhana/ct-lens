// Thin typed client for the ct-lens API. In dev, Vite proxies /api to the
// FastAPI backend (see vite.config.ts), so relative URLs just work.

import type { Results, ScanJob, ScanOptions } from "./types";

async function asJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? detail;
    } catch {
      // response had no JSON body; keep the status text
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export async function startScan(target: string, options: ScanOptions): Promise<ScanJob> {
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, anonymize: options.anonymize }),
  });
  return asJson<ScanJob>(response);
}

export async function getStatus(jobId: string): Promise<ScanJob> {
  return asJson<ScanJob>(await fetch(`/api/scans/${jobId}`));
}

export async function getResults(jobId: string): Promise<Results> {
  return asJson<Results>(await fetch(`/api/scans/${jobId}/results`));
}

export function datasetUrl(jobId: string, format: "csv" | "json"): string {
  return `/api/scans/${jobId}/dataset.${format}`;
}

/**
 * Start a scan and poll until it finishes (or errors). Calls `onStatus` on each
 * poll so the UI can show progress.
 */
export async function runScan(
  target: string,
  options: ScanOptions,
  onStatus: (job: ScanJob) => void,
  intervalMs = 1500,
): Promise<{ job: ScanJob; results: Results }> {
  const created = await startScan(target, options);
  onStatus(created);

  let job = created;
  while (job.status === "pending" || job.status === "running") {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    job = await getStatus(job.id);
    onStatus(job);
  }

  if (job.status === "error") {
    throw new Error(job.error ?? "scan failed");
  }
  const results = await getResults(job.id);
  return { job, results };
}
