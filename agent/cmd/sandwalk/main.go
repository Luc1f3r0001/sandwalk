// Command sandwalk is the Sandwalk endpoint agent: a single binary that runs as
// the root LaunchDaemon and also serves the user-facing CLI.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sandwalk/internal/daemon"
	"sandwalk/internal/uploader"
)

// version is set at build time via -ldflags "-X main.version=..."; falls back to
// the installed VERSION file.
var version = ""

const (
	installDir   = "/opt/sandwalk"
	logFile      = "/var/log/sandwalk/daemon.log"
	dashboardURL = "https://sandwalk.example.com"
	adminUser    = "admin"
	adminPass    = "changeme"
)

func resolveVersion() string {
	if version != "" {
		return version
	}
	if b, err := os.ReadFile(installDir + "/VERSION"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "dev"
}

func main() {
	v := resolveVersion()
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "daemon":
		if err := daemon.Run(v); err != nil {
			fmt.Fprintln(os.Stderr, "daemon error:", err)
			os.Exit(1)
		}
	case "status":
		cmdStatus(v)
	case "scan":
		cmdScan("full")
	case "incremental":
		cmdScan("incremental")
	case "validate-all":
		cmdValidateAll()
	case "findings":
		cmdFindings()
	case "version":
		cmdVersion(v)
	case "update":
		cmdUpdate(v)
	case "logs":
		cmdLogs()
	default:
		usage()
	}
}

func usage() {
	fmt.Println(`sandwalk — endpoint secrets scanner
  sandwalk status          Daemon status and finding counts
  sandwalk scan            Request a full rescan (re-scans every file)
  sandwalk incremental     Request an incremental scan (changed files only — fast)
  sandwalk validate-all    Re-validate every secret on this machine
  sandwalk findings        List open findings
  sandwalk version         Show installed version
  sandwalk update          Download + install the latest version now
  sandwalk logs            Tail daemon logs`)
}

func dashURL() string {
	if u := os.Getenv("DASHBOARD_URL"); u != "" {
		return u
	}
	return dashboardURL
}

func apiGet(path string, out any) bool {
	req, _ := http.NewRequest("GET", dashURL()+path, nil)
	req.SetBasicAuth(adminUser, adminPass)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out) == nil
}

func apiPost(path string, body any, out any) bool {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", dashURL()+path, bytes.NewReader(b))
	req.SetBasicAuth(adminUser, adminPass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	defer resp.Body.Close()
	if out == nil {
		return true
	}
	return json.NewDecoder(resp.Body).Decode(out) == nil
}

func daemonRunning() bool {
	if err := exec.Command("pgrep", "-f", "sandwalk daemon").Run(); err == nil {
		return true
	}
	return false
}

func cmdStatus(v string) {
	if daemonRunning() {
		fmt.Println("Daemon: ✓ running")
	} else {
		fmt.Println("Daemon: ✗ stopped")
	}
	fmt.Println("Version:", v)

	mid := uploader.MachineID()
	var resp struct {
		Machine struct {
			Hostname        string `json:"hostname"`
			Username        string `json:"username"`
			OpenFindings    int    `json:"open_findings"`
			ConfirmedActive int    `json:"confirmed_active"`
			LastSeen        string `json:"last_seen"`
		} `json:"machine"`
	}
	if apiGet("/api/machines/"+mid, &resp) {
		m := resp.Machine
		fmt.Printf("Machine:   %s (%s)\n", m.Hostname, m.Username)
		fmt.Printf("Open:      %d\n", m.OpenFindings)
		fmt.Printf("Confirmed: %d\n", m.ConfirmedActive)
		fmt.Printf("Last seen: %s\n", m.LastSeen)
	} else {
		fmt.Println("Dashboard: not reachable (VPN required)")
	}
}

func cmdScan(scope string) {
	mid := uploader.MachineID()
	var out struct {
		OK        bool   `json:"ok"`
		RequestID string `json:"request_id"`
	}
	label := "Full rescan"
	if scope == "incremental" {
		label = "Incremental scan"
	}
	if apiPost("/api/machines/"+mid+"/rescan", map[string]string{"scope": scope}, &out) && out.OK {
		fmt.Printf("✓ %s requested — agent will pick it up within 10 seconds.\n", label)
	} else {
		fmt.Println("✗ Could not request scan (VPN required).")
	}
}

func cmdValidateAll() {
	mid := uploader.MachineID()
	fmt.Println("Re-validating every secret on this machine...")
	var out struct {
		Total            int `json:"total"`
		Active           int `json:"active"`
		Removed          int `json:"removed"`
		KeptUnverifiable int `json:"kept_unverifiable"`
	}
	if apiPost("/api/machines/"+mid+"/validate-all", map[string]string{}, &out) {
		fmt.Printf("✓ Validated %d secret(s): %d ACTIVE, %d removed (inactive/unverifiable), %d kept (no live validator).\n",
			out.Total, out.Active, out.Removed, out.KeptUnverifiable)
	} else {
		fmt.Println("✗ Could not validate (VPN required).")
	}
}

func cmdFindings() {
	var data []map[string]any
	if !apiGet("/api/findings?status=open&limit=50", &data) {
		fmt.Println("✗ Dashboard not reachable (VPN required)")
		return
	}
	if len(data) == 0 {
		fmt.Println("No open findings.")
		return
	}
	for _, f := range data {
		va := "unverified"
		switch f["verified_active"] {
		case true:
			va = "ACTIVE"
		case false:
			va = "rotated"
		}
		fmt.Printf("  [%-8s] %-22s %v\n", va, f["pattern_id"], f["file_path"])
	}
}

const apiGateway = "https://api.sandwalk.example.com"

// agentKeyFromPlist reads AGENT_KEY out of the LaunchDaemon plist (root-readable).
func agentKeyFromPlist() string {
	if k := os.Getenv("AGENT_KEY"); k != "" {
		return k
	}
	b, err := os.ReadFile("/Library/LaunchDaemons/com.sandwalk.daemon.plist")
	if err != nil {
		return ""
	}
	// Find <key>AGENT_KEY</key><string>VALUE</string>
	s := string(b)
	i := strings.Index(s, "AGENT_KEY")
	if i < 0 {
		return ""
	}
	rest := s[i:]
	open := strings.Index(rest, "<string>")
	close := strings.Index(rest, "</string>")
	if open < 0 || close < 0 || open > close {
		return ""
	}
	return rest[open+len("<string>") : close]
}

// fetchLatest queries the config endpoint for the latest available version.
func fetchLatest(current string) (latest string, needsUpdate bool, ok bool) {
	key := agentKeyFromPlist()
	if key == "" {
		return "", false, false
	}
	req, _ := http.NewRequest("GET", apiGateway+"/sandwalk/config?version="+current, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", false, false
	}
	defer resp.Body.Close()
	var d struct {
		LatestVersion string `json:"latest_version"`
		NeedsUpdate   bool   `json:"needs_update"`
	}
	if json.NewDecoder(resp.Body).Decode(&d) != nil {
		return "", false, false
	}
	return d.LatestVersion, d.NeedsUpdate, true
}

func cmdVersion(current string) {
	fmt.Println("Installed:", current)
	latest, needsUpdate, ok := fetchLatest(current)
	if !ok {
		fmt.Println("(could not reach update server)")
		return
	}
	status := "up to date"
	if needsUpdate {
		status = "update available — run: sandwalk update"
	}
	fmt.Printf("Latest:    %s (%s)\n", latest, status)
}

func cmdUpdate(current string) {
	key := agentKeyFromPlist()
	if key == "" {
		fmt.Println("✗ AGENT_KEY not found — cannot check for updates.")
		return
	}
	req, _ := http.NewRequest("GET", apiGateway+"/sandwalk/config?version="+current, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("✗ Could not reach update server:", err)
		return
	}
	defer resp.Body.Close()
	var d struct {
		LatestVersion string `json:"latest_version"`
		NeedsUpdate   bool   `json:"needs_update"`
		DownloadURL   string `json:"download_url"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	if !d.NeedsUpdate || d.DownloadURL == "" {
		fmt.Printf("✓ Already up to date (%s)\n", current)
		return
	}
	fmt.Printf("Downloading Sandwalk %s...\n", d.LatestVersion)
	pkg := filepath.Join(os.TempDir(), "Sandwalk-"+d.LatestVersion+".pkg")
	if err := downloadFile(d.DownloadURL, pkg); err != nil {
		fmt.Println("✗ Download failed:", err)
		return
	}
	fmt.Println("Installing (requires sudo)...")
	cmd := exec.Command("sudo", "installer", "-pkg", pkg, "-target", "/")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("✗ Install failed:", err)
		return
	}
	fmt.Printf("✓ Sandwalk %s installed. Daemon restarting.\n", d.LatestVersion)
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func cmdLogs() {
	out, err := exec.Command("tail", "-n", "50", logFile).Output()
	if err != nil {
		fmt.Println("No log at", logFile)
		return
	}
	fmt.Print(string(out))
}
