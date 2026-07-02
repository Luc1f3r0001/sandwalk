// Package types holds data structures shared across the agent.
package types

// Finding is the normalized representation of a detected secret, matching the
// dashboard's /api/scans payload schema exactly so the server/DB/UI are unchanged.
type Finding struct {
	PatternID        string   `json:"pattern_id"`
	PatternName      string   `json:"pattern_name"`
	Severity         string   `json:"severity"`
	Category         string   `json:"category"`
	SourceType       string   `json:"source_type"` // "machine" | "git"
	FilePath         string   `json:"file_path"`
	FilePaths        []string `json:"file_paths,omitempty"`
	LineNumber       int      `json:"line_number"`
	ValueHash        string   `json:"value_hash"`
	ValuePreview     string   `json:"value_preview"`
	ContextLine      string   `json:"context_line,omitempty"`
	VerifiedActive   *bool    `json:"verified_active"` // true=active, false=rotated, nil=unverified
	SSHHasPassphrase *bool    `json:"ssh_has_passphrase,omitempty"`
	CommitHash       string   `json:"commit_hash,omitempty"`
	CommitAuthor     string   `json:"commit_author,omitempty"`
	CommitDate       string   `json:"commit_date,omitempty"`

	// Internal only — not serialized to the dashboard, used for lifecycle logic.
	Value string `json:"-"`
}

// MachineInfo identifies the host. Mirrors the v1 get_machine_info() shape.
type MachineInfo struct {
	MachineID    string `json:"machine_id"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
	// FDAGranted is the Full Disk Access self-check result: true=granted,
	// false=denied (TCC EPERM), nil=could not determine. A root daemon never
	// gets a TCC prompt, so this is the only reliable signal that Full Disk Access is granted.
	FDAGranted *bool `json:"fda_granted,omitempty"`
}

// ScanPayload is the body POSTed to /api/scans.
type ScanPayload struct {
	Machine    MachineInfo `json:"machine"`
	Scope      string      `json:"scope"`
	ScannedAt  string      `json:"scanned_at"`
	DurationMs int         `json:"duration_ms"`
	DropHashes []string    `json:"drop_hashes"`
	Findings   []Finding   `json:"findings"`
}
