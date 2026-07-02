package uploader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"sandwalk/internal/types"
)

// FindingRef is a minimal open-finding record fetched from the dashboard, used
// for removed-secret reconciliation. Matching is by ValueHash only — ValuePreview
// is now a REDACTED hint (the server never stores plaintext), so it must never be
// used for validation.
type FindingRef struct {
	ID           string `json:"id"`
	PatternID    string `json:"pattern_id"`
	FilePath     string `json:"file_path"`
	ValueHash    string `json:"value_hash"`
	ValuePreview string `json:"value_preview"`
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest("GET", c.DashboardURL+path, nil)
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s → %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(path string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", c.DashboardURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// OpenFindingsForFile returns the dashboard's open findings for a specific file.
func (c *Client) OpenFindingsForFile(filePath string) ([]FindingRef, error) {
	var all []FindingRef
	q := url.Values{"status": {"open"}, "limit": {"500"}}
	if err := c.get("/api/findings?"+q.Encode(), &all); err != nil {
		return nil, err
	}
	var out []FindingRef
	for _, f := range all {
		if f.FilePath == filePath {
			out = append(out, f)
		}
	}
	return out, nil
}

// OpenActiveFindings returns all open, confirmed-active findings for a machine —
// the input set for the "Validate All" sweep.
func (c *Client) OpenActiveFindings(machineID string) ([]FindingRef, error) {
	var all []struct {
		FindingRef
		MachineID      string `json:"machine_id"`
		VerifiedActive *bool  `json:"verified_active"`
	}
	if err := c.get("/api/findings?status=open&limit=1000", &all); err != nil {
		return nil, err
	}
	var out []FindingRef
	for _, f := range all {
		if f.MachineID == machineID && f.VerifiedActive != nil && *f.VerifiedActive {
			out = append(out, f.FindingRef)
		}
	}
	return out, nil
}

// MarkRemovedActive tags findings whose secret was removed from the file but is
// still live elsewhere — a distinct dashboard status ("removed_active").
func (c *Client) MarkRemovedActive(machineID string, valueHashes []string) error {
	return c.post("/api/findings/mark-removed-active", map[string]any{
		"machine_id": machineID, "value_hashes": valueHashes,
	})
}

// MarkRotated marks findings rotated (confirmed inactive) via the scan drop path.
func (c *Client) MarkRotated(machine types.MachineInfo, scannedAt string, valueHashes []string) error {
	return c.post("/api/scans", map[string]any{
		"machine": machine, "scope": "verification", "scanned_at": scannedAt,
		"drop_hashes": valueHashes, "findings": []any{},
	})
}
