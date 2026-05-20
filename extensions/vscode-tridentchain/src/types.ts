/** Scan summary shape from CLI stdout or MCP tool JSON (unified layer). */
export interface ScanSummary {
  status?: string;
  tool?: string;
  schema_version?: string;
  summary?: Record<string, unknown>;
  findings?: Array<{
    package?: string;
    version?: string;
    vulnerability_count?: number;
    severity?: Record<string, number>;
  }>;
  affected_components?: Array<{
    name: string;
    version: string;
    vulnerabilities: number;
    severity?: Record<string, number>;
  }>;
  output_paths?: Record<string, string | null>;
  report_path?: string;
  raw_summary?: ScanSummary;
}

export type ScanMode = "scan_full" | "scan_project";
