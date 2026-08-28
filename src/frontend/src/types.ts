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

export interface ScanResponse {
  raw_result_count: number;
  findings: Finding[];
}
