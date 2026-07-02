package scanner

import (
	"sandwalk/internal/types"
	"sandwalk/internal/uploader"
)

// Reconcile compares a file's freshly-scanned findings against the dashboard's
// open findings for that file. For every secret that USED to be in the file but
// is now gone, it flags "removed_active" (removed from the file, liveness unknown).
//
// We intentionally do NOT network-validate here: the plaintext is never
// centralized (the server returns only a redacted last-4 hint), and the secret is
// by definition gone from this file, so there's no live value to check. Flagging
// removed_active is the honest, conservative outcome — a human or a full
// re-validation scan resolves it. (Rotations are still detected the normal way:
// a changed file re-scanned inactive → drop_hashes → rotated.)
func Reconcile(filePath string, current []types.Finding, client *uploader.Client, machine types.MachineInfo) {
	open, err := client.OpenFindingsForFile(filePath)
	if err != nil || len(open) == 0 {
		return
	}
	currentHashes := map[string]bool{}
	for _, f := range current {
		currentHashes[f.ValueHash] = true
	}

	var removedActive []string
	for _, old := range open {
		if !currentHashes[old.ValueHash] {
			removedActive = append(removedActive, old.ValueHash)
		}
	}
	if len(removedActive) > 0 {
		client.MarkRemovedActive(machine.MachineID, removedActive)
	}
}
