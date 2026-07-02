// Package uploader handles machine identity and all HTTP communication with the
// dashboard / API Gateway.
package uploader

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"sandwalk/internal/types"
)

// namespaceDNS is RFC 4122's DNS namespace, matching Python's uuid.NAMESPACE_DNS.
var namespaceDNS = [16]byte{
	0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// uuid5 reproduces Python's uuid.uuid5(NAMESPACE_DNS, name).
func uuid5(name string) string {
	h := sha1.New()
	h.Write(namespaceDNS[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)[:16]
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

var (
	cachedUserMu sync.Mutex
	cachedUser   string
)

func isSystemUser(u string) bool {
	switch u {
	case "", "root", "loginwindow", "_mbsetupuser", "_windowserver":
		return true
	}
	return strings.HasPrefix(u, "_")
}

// humanUnderUsers returns the single human account under /Users (the Mac's owner),
// ignoring Shared and dotfiles. Robust fallback when the console is momentarily
// owned by a system account (screen lock, login window, fast user switching).
func humanUnderUsers() string {
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() && n != "Shared" && !strings.HasPrefix(n, ".") {
			return n
		}
	}
	return ""
}

// consoleUser returns the human owner of the machine, NOT the daemon's euid
// (root). It caches the first real user so the machine identity is stable for
// the daemon's lifetime, immune to transient root ownership of /dev/console.
func consoleUser() string {
	cachedUserMu.Lock()
	defer cachedUserMu.Unlock()
	if cachedUser != "" {
		return cachedUser
	}
	// 1. Owner of the GUI console (absolute path — daemon env may lack PATH).
	if out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output(); err == nil {
		if u := string(bytes.TrimSpace(out)); !isSystemUser(u) {
			cachedUser = u
			return u
		}
	}
	// 2. The single human account under /Users.
	if u := humanUnderUsers(); u != "" {
		cachedUser = u
		return u
	}
	// 3. Last resort.
	if u, err := user.Current(); err == nil && !isSystemUser(u.Username) {
		cachedUser = u.Username
		return u.Username
	}
	return "unknown" // not cached — keep trying next time
}

// MachineID returns the stable UUID5(hostname:consoleUser) used by the dashboard.
func MachineID() string {
	host, _ := os.Hostname()
	return uuid5(host + ":" + consoleUser())
}

// Machine builds the MachineInfo block sent with every scan.
func Machine(agentVersion string) types.MachineInfo {
	host, _ := os.Hostname()
	username := consoleUser()
	return types.MachineInfo{
		MachineID:    MachineID(),
		Hostname:     host,
		Username:     username,
		OS:           runtime.GOOS,
		OSVersion:    osVersion(),
		AgentVersion: agentVersion,
		FDAGranted:   fdaGranted(),
	}
}

// fdaGranted probes whether the daemon actually has Full Disk Access, by trying
// to read a location gated by SystemPolicyAllFiles. A root LaunchDaemon never
// receives a TCC prompt, so this is the only reliable signal that Full Disk Access
// is granted. Returns true (readable → granted), false (EPERM → denied), or
// nil (inconclusive).
func fdaGranted() *bool {
	t, f := true, false
	// Primary: opening the system TCC database for read is gated by Full Disk
	// Access and returns EPERM when denied. It always exists on macOS.
	if fh, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db"); err == nil {
		fh.Close()
		return &t
	} else if isPermErr(err) {
		return &f
	}
	// Fallback (only if the primary was inconclusive, e.g. path moved): LIST the
	// console user's ~/Downloads. TCC gates the directory READ (readdir), NOT a
	// bare open() of the directory node — so os.ReadDir is required; a plain
	// os.Open would falsely succeed regardless of FDA and report a wrong "granted".
	if u := consoleUser(); u != "" && u != "unknown" {
		if _, err := os.ReadDir("/Users/" + u + "/Downloads"); err == nil {
			return &t
		} else if isPermErr(err) {
			return &f
		}
	}
	return nil // inconclusive
}

// isPermErr reports whether err is a permission denial — macOS TCC surfaces
// denials as EPERM (also accept EACCES / os.ErrPermission defensively).
func isPermErr(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission)
}

// Client posts to the API Gateway / dashboard.
type Client struct {
	ServerURL    string
	DashboardURL string
	AgentKey     string
	http         *http.Client
}

func New(serverURL, dashboardURL, agentKey string) *Client {
	return &Client{
		ServerURL:    serverURL,
		DashboardURL: dashboardURL,
		AgentKey:     agentKey,
		http:         &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) headers(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.AgentKey)
	req.Header.Set("X-Agent-Key", c.AgentKey)
}

// maxFindingsPerMsg keeps each /api/scans body well under SQS's 256 KB message
// limit. A single payload of hundreds of findings was silently rejected by the
// API Gateway, losing the whole scan.
const maxFindingsPerMsg = 20

// Upload posts findings (and drop hashes) to /api/scans, automatically chunking
// large finding sets across multiple messages so none exceeds the SQS limit.
func (c *Client) Upload(payload types.ScanPayload) error {
	findings := payload.Findings
	drops := payload.DropHashes

	if len(findings) <= maxFindingsPerMsg {
		return c.send(payload)
	}
	for i := 0; i < len(findings); i += maxFindingsPerMsg {
		end := min(i+maxFindingsPerMsg, len(findings))
		p := payload
		p.Findings = findings[i:end]
		if i == 0 {
			p.DropHashes = drops // attach drops to the first chunk only
		} else {
			p.DropHashes = nil
		}
		if err := c.send(p); err != nil {
			return err
		}
	}
	return nil
}

// send posts one scan message and verifies the HTTP status (the previous code
// ignored it, so a rejected upload looked successful).
func (c *Client) send(payload types.ScanPayload) error {
	if payload.Findings == nil {
		payload.Findings = []types.Finding{} // [] not null — consumer len()s it
	}
	if payload.DropHashes == nil {
		payload.DropHashes = []string{}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c.ServerURL+"/api/scans", bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.headers(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("upload rejected: HTTP %d (body %d bytes)", resp.StatusCode, len(body))
	}
	return nil
}

// MarkFixed tells the dashboard a set of findings were removed from their files.
func (c *Client) MarkFixed(machineID string, valueHashes []string, note string) error {
	body, _ := json.Marshal(map[string]any{
		"machine_id":   machineID,
		"value_hashes": valueHashes,
		"note":         note,
	})
	req, err := http.NewRequest("POST", c.DashboardURL+"/api/findings/mark-fixed", bytes.NewReader(body))
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

func osVersion() string {
	out, err := exec.Command("/usr/bin/uname", "-v").Output()
	if err == nil {
		return string(bytes.TrimSpace(out))
	}
	return runtime.GOOS
}
