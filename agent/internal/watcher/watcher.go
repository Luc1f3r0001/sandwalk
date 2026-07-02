// Package watcher provides a real-time macOS FSEvents watcher. On each file
// create/modify it scans that single file with Kingfisher and uploads active
// findings immediately, then reconciles any secrets removed from the file.
package watcher

import (
	"log"
	"sync"
	"time"

	"github.com/fsnotify/fsevents"
	"sandwalk/internal/config"
	"sandwalk/internal/manifest"
	"sandwalk/internal/scanner"
	"sandwalk/internal/types"
	"sandwalk/internal/uploader"
)

// Watcher watches the filesystem and scans changed files in real time.
type Watcher struct {
	cfg          *config.Config
	client       *uploader.Client
	agentVersion string

	mu       sync.Mutex
	debounce map[string]time.Time
}

func New(cfg *config.Config, client *uploader.Client, agentVersion string) *Watcher {
	return &Watcher{cfg: cfg, client: client, agentVersion: agentVersion, debounce: map[string]time.Time{}}
}

// Start begins watching root and blocks until the stream ends.
func (w *Watcher) Start(root string) error {
	dev, err := fsevents.DeviceForPath(root)
	if err != nil {
		dev = 0
	}
	es := &fsevents.EventStream{
		Paths:   []string{root},
		Latency: 500 * time.Millisecond,
		Device:  dev,
		Flags:   fsevents.FileEvents | fsevents.WatchRoot,
	}
	if err := es.Start(); err != nil {
		return err
	}
	log.Printf("FSEvents watcher started on %s", root)
	for msg := range es.Events {
		for _, ev := range msg {
			w.handle(ev)
		}
	}
	return nil
}

func (w *Watcher) handle(ev fsevents.Event) {
	created := ev.Flags&fsevents.ItemCreated != 0
	modified := ev.Flags&fsevents.ItemModified != 0
	renamed := ev.Flags&fsevents.ItemRenamed != 0
	isFile := ev.Flags&fsevents.ItemIsFile != 0
	if !isFile || !(created || modified || renamed) {
		return
	}
	path := "/" + ev.Path // fsevents reports device-relative paths without leading slash
	if ev.Path[0] == '/' {
		path = ev.Path
	}
	if !manifest.Watchable(path, w.cfg.ExcludePaths()) {
		return
	}

	// Debounce: collapse rapid repeated events on the same file.
	now := time.Now()
	w.mu.Lock()
	if last, ok := w.debounce[path]; ok && now.Sub(last) < 3*time.Second {
		w.mu.Unlock()
		return
	}
	w.debounce[path] = now
	w.mu.Unlock()

	go w.scanFile(path)
}

func (w *Watcher) scanFile(path string) {
	findings, err := scanner.Run([]string{path}, w.cfg)
	if err != nil {
		return
	}
	machine := uploader.Machine(w.agentVersion)

	// Reconcile secrets that used to be in this file but are gone now.
	scanner.Reconcile(path, findings, w.client, machine)

	upload, dropHashes := scanner.Split(findings)
	if len(upload) == 0 && len(dropHashes) == 0 {
		return
	}
	payload := types.ScanPayload{
		Machine:    machine,
		Scope:      "realtime",
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		DropHashes: dropHashes,
		Findings:   upload,
	}
	payload.Machine.MachineID = machine.MachineID
	if err := w.client.Upload(payload); err != nil {
		log.Printf("watcher upload error: %v", err)
		return
	}
	log.Printf("watcher: %s → %d finding(s)", path, len(upload))
}
