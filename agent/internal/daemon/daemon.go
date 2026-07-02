// Package daemon is the root LaunchDaemon: it runs the real-time watcher, an
// initial baseline scan, a daily incremental sweep, rescan handling, and
// auto-update — all built around the SQLite manifest.
package daemon

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandwalk/internal/config"
	"sandwalk/internal/manifest"
	"sandwalk/internal/patterns"
	"sandwalk/internal/scanner"
	"sandwalk/internal/types"
	"sandwalk/internal/uploader"
	"sandwalk/internal/watcher"
)

const (
	manifestPath  = "/var/db/sandwalk/manifest.sqlite"
	lastSweepPath = "/var/db/sandwalk/last_sweep" // wall-clock anchor for the daily sweep
	pollInterval  = 10 * time.Second
	policyEvery   = 180 // poll ticks between policy fetches (~30 min)
	dailyInterval = 24 * time.Hour
)

// Daemon ties the components together.
type Daemon struct {
	cfg     *config.Config
	client  *uploader.Client
	store   *manifest.Store
	version string

	scanMu sync.Mutex // only one full/incremental scan at a time
}

func Run(version string) error {
	cfg := config.Load()
	client := uploader.New(cfg.ServerURL, cfg.DashboardURL, cfg.AgentKey)

	_ = os.MkdirAll("/var/db/sandwalk", 0o755)
	store, err := manifest.Open(manifestPath)
	if err != nil {
		return err
	}
	defer store.Close()

	d := &Daemon{cfg: cfg, client: client, store: store, version: version}

	// Apply policy before anything scans (race-free startup).
	if _, _, _, err := cfg.FetchPolicy(version); err != nil {
		log.Printf("policy fetch failed (using defaults): %v", err)
	} else {
		log.Printf("policy applied: version=%s", cfg.PolicyVersion())
	}

	// Register immediately so the dashboard reflects this agent version even
	// before the first findings upload.
	d.register()

	// Real-time watcher.
	go func() {
		w := watcher.New(cfg, client, version)
		if err := w.Start("/"); err != nil {
			log.Printf("watcher error: %v", err)
		}
	}()

	// Initial baseline (manifest is empty on first install).
	go d.sweep("baseline")

	// Daily incremental sweep + re-validation.
	go d.dailyLoop()

	// Rescan + update polling.
	d.pollLoop()
	return nil
}

func (d *Daemon) scanRoots() []string {
	if os.Geteuid() == 0 {
		return []string{"/"}
	}
	home, _ := os.UserHomeDir()
	return []string{home}
}

// sweep performs an incremental scan: plan changed files, scan them, upload
// active findings, mark deleted-file findings fixed, and update the manifest.
// It returns true only if the scan actually RAN (false when another scan holds
// the lock) so callers like the rescan handler don't mark work "done" that never
// happened.
func (d *Daemon) sweep(scope string) bool {
	if !d.scanMu.TryLock() {
		log.Printf("scan already in progress — skipping %s", scope)
		return false
	}
	defer d.scanMu.Unlock()

	// Forced full rescan: wipe the manifest AFTER acquiring the lock, so a rescan
	// that gets skipped for lock contention can never leave the manifest empty
	// (which would corrupt incremental state until the next full walk).
	if scope == "full" {
		if err := d.store.Clear(); err != nil {
			log.Printf("manifest clear error: %v", err)
		}
	}

	start := time.Now()
	roots := d.scanRoots()
	excludes := d.cfg.ExcludePaths()
	ruleset := patterns.RulesetVersion(d.cfg.DisabledPatterns())

	toScan, gitRepos, deleted, err := d.store.Plan(roots, excludes, ruleset)
	if err != nil {
		log.Printf("manifest plan error: %v", err)
		return false
	}
	log.Printf("%s sweep: %d changed file(s), %d git repo(s), %d deleted", scope, len(toScan), len(gitRepos), len(deleted))

	if len(toScan) > 0 {
		findings, err := scanner.Run(toScan, d.cfg)
		if err != nil {
			log.Printf("scan error: %v", err)
		} else {
			d.uploadFindings(findings, scope)
		}
	}

	// Git history: scan repos whose commit history changed (auto-detected .git).
	if len(gitRepos) > 0 {
		findings, err := scanner.RunGit(gitRepos, d.cfg)
		if err != nil {
			log.Printf("git scan error: %v", err)
		} else {
			d.uploadFindings(findings, scope+":git")
		}
	}

	// Deleted files: their open findings can't be in the file anymore.
	if len(deleted) > 0 {
		d.handleDeleted(deleted)
		d.store.Forget(deleted)
	}

	// Update manifest so the next sweep skips unchanged files.
	if err := d.store.Record(roots, excludes, ruleset); err != nil {
		log.Printf("manifest record error: %v", err)
	}
	// Truncate the WAL — Record() commits ~900K upserts in one transaction that
	// passive autocheckpoint can't reset, so the -wal file grows unbounded.
	if err := d.store.Checkpoint(); err != nil {
		log.Printf("manifest checkpoint error: %v", err)
	}
	// Anchor the daily-sweep clock: any completed sweep counts as coverage.
	d.markSwept()
	log.Printf("%s sweep complete in %s", scope, time.Since(start).Truncate(time.Second))
	return true
}

// lastSweepTime reads the persisted wall-clock time of the last completed sweep.
// A zero time (missing/invalid file) forces the daily loop to run one promptly.
func (d *Daemon) lastSweepTime() time.Time {
	b, err := os.ReadFile(lastSweepPath)
	if err != nil {
		return time.Time{}
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// markSwept persists the wall-clock time of a just-completed sweep so the daily
// schedule survives daemon restarts and laptop sleep (unlike a from-boot timer).
func (d *Daemon) markSwept() {
	if err := os.WriteFile(lastSweepPath, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644); err != nil {
		// A persistently unwritable anchor would make dailyLoop over-fire hourly
		// (harmless to coverage, wasteful) — surface it rather than swallow it.
		log.Printf("markSwept: could not persist last-sweep time: %v", err)
	}
}

func (d *Daemon) uploadFindings(findings []types.Finding, scope string) {
	upload, dropHashes := scanner.Split(findings)
	if len(upload) == 0 && len(dropHashes) == 0 {
		return
	}
	machine := uploader.Machine(d.version)
	payload := types.ScanPayload{
		Machine:    machine,
		Scope:      scope,
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		DurationMs: 0,
		DropHashes: dropHashes,
		Findings:   upload,
	}
	if err := d.client.Upload(payload); err != nil {
		log.Printf("upload error: %v", err)
		return
	}
	log.Printf("%s: uploaded %d active, %d rotated", scope, len(upload), len(dropHashes))
}

// handleDeleted reconciles findings whose files were deleted: re-validate each
// (still active → removed_active tag; rotated → fixed).
func (d *Daemon) handleDeleted(paths []string) {
	machine := uploader.Machine(d.version)
	for _, p := range paths {
		scanner.Reconcile(p, nil, d.client, machine)
	}
}

// register uploads machine info (no findings) so the dashboard shows the current
// agent version and last-seen immediately on startup.
func (d *Daemon) register() {
	payload := types.ScanPayload{
		Machine:    uploader.Machine(d.version),
		Scope:      "register",
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		DropHashes: []string{},
		Findings:   []types.Finding{},
	}
	if err := d.client.Upload(payload); err != nil {
		log.Printf("register error: %v", err)
		return
	}
	log.Printf("registered machine as %s (v%s)", uploader.Machine(d.version).Username, d.version)
}

// dailyLoop guarantees at least one incremental sweep every 24h of WALL-CLOCK
// time. It checks hourly and compares against the persisted last-sweep timestamp
// (not a from-boot monotonic ticker), so the daily guarantee survives daemon
// restarts and laptop sleep — where a monotonic ticker would reset or freeze and
// never elapse. Any sweep (baseline/rescan/daily) refreshes the anchor, so this
// only fires when the machine has genuinely gone 24h without one.
func (d *Daemon) dailyLoop() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		if time.Since(d.lastSweepTime()) >= dailyInterval {
			d.sweep("daily")
		}
	}
}
