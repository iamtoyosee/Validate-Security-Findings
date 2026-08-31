// Mirrors NormalizedFinding in src/schemas.py, minus the `raw` field which the
// API strips before serializing.
export interface Finding {
  finding_id: string;
  source_scanner: string;
  rule_ids: string[];
  vulnerability_type: string;
  cwe: string[];
  severity: string;
  file_path: string;
  line_start: number;
  line_end: number | null;
  column_start: number | null;
  message: string;
  code_snippet: string | null;
}

export interface ReachabilityVerdict {
  finding_id: string;
  status: "reachable" | "unreachable" | "unknown";
  confidence: "high" | "medium" | "low";
  containing_function: string | null;
  entry_point: string | null;
  call_path: string[] | null;
  reason: string;
}

export interface SampleApp {
  id: string;
  name: string;
  description: string;
}

export interface ScanResponse {
  raw_result_count: number;
  findings: Finding[];
  reachability: ReachabilityVerdict[];
}
