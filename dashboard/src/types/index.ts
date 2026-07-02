export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "open" | "fixed" | "rotated" | "removed_active";

export interface ValidateAllResult {
  dispatched: boolean;
  request_id?: string;
  message: string;
}
export type Category =
  | "cloud" | "vcs" | "payment" | "database" | "saas" | "ai" | "crypto" | "auth" | "generic";

export interface Machine {
  id: string;
  hostname: string;
  username: string;
  os: string;
  first_seen: string;
  last_seen: string;
  scan_count: number;
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  total_open: number;
  agent_version?: string;
  fda_granted?: boolean | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  machine_id: string;
  hostname: string;
  username: string;
  pattern_id: string;
  pattern_name: string;
  severity: Severity;
  category: Category;
  source_type: "machine" | "git";
  file_path: string;
  file_paths?: string[];
  line_number: number | null;
  value_hash: string;
  value_preview: string;
  context_line: string | null;
  verified_active: boolean | null;
  ssh_has_passphrase: boolean | null;
  first_seen: string;
  last_seen: string;
  status: FindingStatus;
  remediated_at: string | null;
  notes: string | null;
  commit_hash: string | null;
  commit_author: string | null;
  commit_date: string | null;
  blast_radius: string | null;
  remediation: string | null;
}

export interface Stats {
  total_machines: number;
  scanned_last_7d: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  machine_findings: number;
  git_findings: number;
  findings_by_category: Record<string, number>;
  top_finding_types: Array<{ name: string; count: number }>;
}
