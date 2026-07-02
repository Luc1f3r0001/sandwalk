package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sandwalk/internal/uploader"
)

const apiGateway = "https://api.sandwalk.example.com"

// autoUpdateDisableMarker, when present on disk, turns OFF the agent's self-update.
// Used for pinned / test installs (e.g. a signed 1.3.0 under evaluation) so the S3
// channel can't revert them to an older published version. Remove the file to
// re-enable auto-update.
const autoUpdateDisableMarker = "/opt/sandwalk/DISABLE_AUTOUPDATE"

// pollLoop checks for admin rescans and auto-updates on a fixed cadence.
func (d *Daemon) pollLoop() {
	machineID := uploader.MachineID()
	ticks := 0
	for {
		d.checkRescan(machineID)
		d.checkUpdate()
		if ticks%policyEvery == 0 {
			if _, _, _, err := d.cfg.FetchPolicy(d.version); err == nil {
				log.Printf("policy refreshed: version=%s", d.cfg.PolicyVersion())
			}
		}
		ticks++
		time.Sleep(pollInterval)
	}
}

type rescanResp struct {
	Pending   bool   `json:"pending"`
	Scope     string `json:"scope"`
	RequestID string `json:"request_id"`
}

func (d *Daemon) checkRescan(machineID string) {
	req, _ := http.NewRequest("GET", d.cfg.DashboardURL+"/api/rescan/pending", nil)
	req.Header.Set("Authorization", "Bearer "+d.cfg.AgentKey)
	req.Header.Set("X-Agent-Key", d.cfg.AgentKey)
	req.Header.Set("X-Machine-ID", machineID)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var r rescanResp
	if json.NewDecoder(resp.Body).Decode(&r) != nil || !r.Pending {
		return
	}
	log.Printf("admin rescan requested (scope=%s)", r.Scope)
	// sweep() performs the scope=="full" manifest wipe itself, AFTER it acquires
	// the scan lock — so a rescan that gets skipped for lock contention neither
	// wipes the manifest nor gets marked done. Only fulfill when the sweep RAN;
	// otherwise leave the request pending and the next poll (~10s) retries it
	// once the in-flight scan finishes.
	if !d.sweep(r.Scope) {
		log.Printf("rescan deferred — a scan is already running; will retry")
		return
	}
	if r.RequestID != "" {
		fr, _ := http.NewRequest("POST", d.cfg.DashboardURL+"/api/rescan/"+r.RequestID+"/fulfill", nil)
		fr.Header.Set("Authorization", "Bearer "+d.cfg.AgentKey)
		fr.Header.Set("X-Agent-Key", d.cfg.AgentKey)
		if resp, err := client.Do(fr); err == nil {
			resp.Body.Close()
		}
	}
}

type configResp struct {
	LatestVersion string `json:"latest_version"`
	NeedsUpdate   bool   `json:"needs_update"`
	DownloadURL   string `json:"download_url"`
}

func (d *Daemon) checkUpdate() {
	if _, err := os.Stat(autoUpdateDisableMarker); err == nil {
		return // auto-update disabled for this install (kill-switch marker present)
	}
	req, _ := http.NewRequest("GET", apiGateway+"/sandwalk/config?version="+d.version, nil)
	req.Header.Set("Authorization", "Bearer "+d.cfg.AgentKey)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var cr configResp
	if json.NewDecoder(resp.Body).Decode(&cr) != nil || !cr.NeedsUpdate || cr.DownloadURL == "" {
		return
	}
	// Downgrade guard (defense-in-depth behind the DISABLE_AUTOUPDATE marker):
	// never install a version <= the one we're running. Numeric semver compare —
	// a lexical test is wrong ("1.2.9" < "1.2.0" is false; "1.10.0" < "1.2.0" is true).
	if cr.LatestVersion == "" || cmpVer(cr.LatestVersion, d.version) <= 0 {
		return
	}
	log.Printf("auto-update: downloading v%s", cr.LatestVersion)
	pkg := filepath.Join(os.TempDir(), fmt.Sprintf("Sandwalk-%s.pkg", cr.LatestVersion))
	if err := download(cr.DownloadURL, pkg); err != nil {
		log.Printf("auto-update download failed: %v", err)
		return
	}
	log.Printf("auto-update: installing %s (detached)", pkg)
	// Run the installer in a NEW SESSION (detached). The installer's preinstall
	// stops THIS daemon; if the installer were our child it would die with us and
	// launchd's KeepAlive could resurrect the OLD binary mid-install, leaving a
	// rogue daemon. Detached, the install completes and starts one clean daemon.
	cmd := exec.Command("/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("auto-update install failed to start: %v", err)
		return
	}
	log.Printf("auto-update: install launched for v%s — this daemon will be replaced", cr.LatestVersion)
	// Do not Wait — the installer will terminate this process.
}

// cmpVer compares dotted numeric versions ("1.3.0" vs "1.2.9") segment-by-segment.
// Returns -1 if a<b, 0 if equal, 1 if a>b. Non-numeric/short segments read as 0.
func cmpVer(a, b string) int {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVer(v string) [3]int {
	var out [3]int
	for i, seg := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimFunc(seg, func(r rune) bool { return r < '0' || r > '9' }))
		out[i] = n
	}
	return out
}

func download(url, dest string) error {
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
