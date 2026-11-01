// Types mirroring the ct-lens API's JSON responses (see ct_lens/api/app.py).

export type Severity = "high" | "medium" | "low" | "info";
export type JobStatus = "pending" | "running" | "done" | "error";

export interface ScanJob {
  id: string;
  target: string;
  status: JobStatus;
  created_at: string;
  error: string | null;
}

export interface CAShare {
  issuer: string;
  count: number;
  share: number; // 0..1
}

export interface LifetimeStats {
  count: number;
  min_days: number | null;
  max_days: number | null;
  mean_days: number | null;
  median_days: number | null;
  // Serialised from Python tuples -> [label, count] pairs.
  buckets: [string, number][];
}

export interface PeriodCount {
  period: string;
  count: number;
}

export interface Finding {
  category: string;
  severity: Severity;
  domain: string;
  summary: string;
  cert_id: number;
  issuer: string;
  reference: string | null;
}

export interface Results {
  pattern: string;
  total_certificates: number;
  unique_domains: number;
  wildcard_count: number;
  ca_shares: CAShare[];
  lifetimes: LifetimeStats;
  issuance_by_month: PeriodCount[];
  key_types: [string, number][];
  signature_algorithms: [string, number][];
  ca_concentration: { top1: number; top3: number };
  findings: Finding[];
}

export interface ScanOptions {
  anonymize: boolean;
}
