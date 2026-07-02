// Package scanner orchestrates Kingfisher scans under the active policy and
// applies Sandwalk-specific finding rules (SSH passphrase filtering).
package scanner

import (
	"sandwalk/internal/config"
	"sandwalk/internal/kingfisher"
	"sandwalk/internal/patterns"
	"sandwalk/internal/types"
)

// Run scans the given file targets under the current policy (source_type=machine).
func Run(targets []string, cfg *config.Config) ([]types.Finding, error) {
	return run(targets, cfg, "machine")
}

// RunGit scans git repository directories — Kingfisher auto-detects .git and
// walks commit HISTORY, surfacing secrets that were committed then deleted from
// the working tree. Findings are tagged source_type=git.
func RunGit(repoDirs []string, cfg *config.Config) ([]types.Finding, error) {
	return run(repoDirs, cfg, "git")
}

func run(targets []string, cfg *config.Config, sourceType string) ([]types.Finding, error) {
	opts := kingfisher.Options{
		RuleIDs:    patterns.EnabledRuleIDs(cfg.DisabledPatterns()),
		Validate:   cfg.Validate(),
		OnlyValid:  false, // we want rotated ones too, to mark them rotated
		Confidence: "low",
		MaxFileMB:  2,
		SourceType: sourceType,
	}
	findings, err := kingfisher.Scan(targets, opts)
	if err != nil {
		return nil, err
	}
	// Override Kingfisher's unreliable built-in validators (e.g. Anthropic 404s on
	// live keys) with authoritative checks before the validate-or-remove filter runs.
	findings = applyCustomValidators(findings, cfg)
	// Deduplicate: Kingfisher can emit multiple matches for the same secret inside
	// the same file (e.g. an Ed25519 key file matches both the private-key block and
	// the embedded public key, producing two different value_hashes for one actual
	// secret). Keep one finding per (file_path, pattern_id) — prefer the one with
	// richer metadata (SSHHasPassphrase set, or VerifiedActive set).
	findings = dedup(findings)
	return applySSHPolicy(findings, cfg), nil
}

// dedup collapses multiple findings for the same (file_path, pattern_id) into one.
// For SSH keys this removes the spurious second match Kingfisher emits per key file.
func dedup(findings []types.Finding) []types.Finding {
	type key struct{ path, patternID string }
	seen := make(map[key]int) // key → index in out
	out := findings[:0]
	for _, f := range findings {
		k := key{f.FilePath, f.PatternID}
		if idx, exists := seen[k]; exists {
			// Prefer the richer finding: SSHHasPassphrase set beats unset,
			// VerifiedActive set beats nil.
			existing := out[idx]
			if (f.SSHHasPassphrase != nil && existing.SSHHasPassphrase == nil) ||
				(f.VerifiedActive != nil && existing.VerifiedActive == nil) {
				out[idx] = f
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}

// applySSHPolicy drops passphrase-protected SSH/TLS keys when policy says to only
// report passphrase-less keys (the genuinely dangerous case).
func applySSHPolicy(findings []types.Finding, cfg *config.Config) []types.Finding {
	if !cfg.SSHRequireNoPassphrase() {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if f.PatternID == "ssh_private_key" && f.SSHHasPassphrase != nil && *f.SSHHasPassphrase {
			continue // encrypted key → skip when policy requires no-passphrase
		}
		out = append(out, f)
	}
	return out
}

// Split enforces the validate-or-remove policy: only confirmed-active secrets are
// uploaded (flagged). Confirmed-inactive ones become drop_hashes so the server
// closes them as rotated. Findings we could NOT validate (VerifiedActive==nil)
// are dropped silently — if it can't be validated, it isn't flagged.
//
// SSH/TLS private keys are the one exception: they have no network validator, so
// kingfisher.go stamps the owner's own ~/.ssh keys as active-by-presence — that
// makes them VerifiedActive==true here, so they upload like any active secret.
// Private keys outside ~/.ssh are already dropped at scan time.
func Split(findings []types.Finding) (upload []types.Finding, dropHashes []string) {
	for _, f := range findings {
		switch {
		case f.VerifiedActive != nil && *f.VerifiedActive:
			upload = append(upload, f) // confirmed active → flag it
		case f.VerifiedActive != nil: // explicitly inactive → rotated/close
			dropHashes = append(dropHashes, f.ValueHash)
		default: // nil → unvalidatable → not flagged (validate-or-remove)
		}
	}
	return upload, dropHashes
}
