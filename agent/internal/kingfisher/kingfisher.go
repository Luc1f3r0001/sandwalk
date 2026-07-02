// Package kingfisher wraps the Kingfisher CLI: it runs scans, parses the JSONL
// output, and maps each finding into Sandwalk's normalized Finding schema.
package kingfisher

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"sandwalk/internal/patterns"
	"sandwalk/internal/types"
)

// sshKeyPathRe matches private keys that are a machine owner's OWN ssh keys —
// those living under a user's ~/.ssh (or root's). Random "BEGIN PRIVATE KEY"
// blobs in caches, app bundles, or test fixtures are NOT owner credentials and
// are dropped. /etc/ssh host keys are intentionally excluded.
var sshKeyPathRe = regexp.MustCompile(`(?:/Users/[^/]+|/home/[^/]+|/var/root|/root)/\.ssh/`)

// Bin is the path to the bundled Kingfisher binary. Overridable via the
// SANDWALK_KINGFISHER env var (used for local testing).
var Bin = func() string {
	if p := os.Getenv("SANDWALK_KINGFISHER"); p != "" {
		return p
	}
	return "/opt/sandwalk/bin/kingfisher"
}()

// kfFinding mirrors one Kingfisher JSONL record.
type kfFinding struct {
	Rule struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"rule"`
	Finding struct {
		Snippet     string `json:"snippet"`
		Fingerprint string `json:"fingerprint"`
		Confidence  string `json:"confidence"`
		Entropy     string `json:"entropy"`
		Validation  struct {
			Status   string `json:"status"`
			Response string `json:"response"`
		} `json:"validation"`
		Language    string `json:"language"`
		Line        int    `json:"line"`
		ColumnStart int    `json:"column_start"`
		ColumnEnd   int    `json:"column_end"`
		Path        string `json:"path"`
		// Git commit context — emitted by Kingfisher when --commit-metadata=true
		// (the default). Populated only for source_type=git findings.
		GitMetadata *struct {
			CommitHash string `json:"commit_hash"`
			CommitDate string `json:"commit_date"`
			Committer  struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"committer"`
		} `json:"git_metadata"`
	} `json:"finding"`
}

// Options controls a scan invocation.
type Options struct {
	RuleIDs    []string // Kingfisher rule IDs to enable (--rule)
	Validate   bool     // run live validation; false → --no-validate
	OnlyValid  bool     // emit only active secrets (--only-valid)
	Confidence string   // low | medium | high (default "low")
	MaxFileMB  int      // --max-file-size
	SourceType string   // finding source_type: "machine" (default) or "git"
}

// HashValue mirrors v1's utils.hash_value so dashboard dedup stays consistent.
func HashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + fmt.Sprintf("%x", sum)
}

func normalize(v string) string {
	return strings.Trim(strings.TrimSpace(v), "\"'`")
}

// maskValue redacts a secret to a prefix + last-4 hint so plaintext never leaves
// the endpoint while the provider is still recognizable:
//   "sk-ant-api03-…long…MIJS" -> "sk-ant-…MIJS".
// Short values reveal less. Must match the consumer + scans.py _mask().
func maskValue(v string) string {
	switch {
	case len(v) <= 4:
		return "…"
	case len(v) < 14: // too short to show a prefix without leaking most of it
		return "…" + v[len(v)-4:]
	default:
		return v[:7] + "…" + v[len(v)-4:]
	}
}

// statusToVerified maps Kingfisher's validation.status to our tri-state.
func statusToVerified(status string) *bool {
	s := strings.ToLower(status)
	t, f := true, false
	switch {
	case strings.Contains(s, "inactive"):
		return &f
	case strings.Contains(s, "active"):
		return &t
	default:
		// "Not Attempted", "Canary Token (Skipped)", empty → cannot determine
		return nil
	}
}

const chunkSize = 256 // bound argv length when scanning many changed files

// Scan runs Kingfisher over the given targets (files or directories) and returns
// normalized findings. Large target lists are scanned in chunks to keep argv
// within OS limits. Targets are passed explicitly so the caller (incremental
// sweep) controls exactly which files are scanned.
func Scan(targets []string, opts Options) ([]types.Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if len(targets) > chunkSize {
		var all []types.Finding
		for i := 0; i < len(targets); i += chunkSize {
			end := i + chunkSize
			if end > len(targets) {
				end = len(targets)
			}
			fs, err := scanChunk(targets[i:end], opts)
			if err != nil {
				return all, err
			}
			all = append(all, fs...)
		}
		return all, nil
	}
	return scanChunk(targets, opts)
}

func scanChunk(targets []string, opts Options) ([]types.Finding, error) {
	conf := opts.Confidence
	if conf == "" {
		conf = "low"
	}
	args := []string{"scan", "--format", "jsonl", "--confidence", conf, "--no-update-check"}
	if !opts.Validate {
		args = append(args, "--no-validate")
	}
	if opts.OnlyValid {
		args = append(args, "--only-valid")
	}
	if opts.MaxFileMB > 0 {
		args = append(args, "--max-file-size", fmt.Sprintf("%d", opts.MaxFileMB))
	}
	for _, r := range opts.RuleIDs {
		args = append(args, "--rule", r)
	}
	args = append(args, targets...)

	cmd := exec.Command(Bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []types.Finding
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var kf kfFinding
		if err := json.Unmarshal([]byte(line), &kf); err != nil {
			continue
		}
		if kf.Rule.ID == "" { // summary line, not a finding
			continue
		}
		patternID, ok := patterns.PatternForRule(kf.Rule.ID)
		if !ok {
			continue // not a detector we report on
		}
		meta, _ := patterns.Meta(patternID)

		srcType := opts.SourceType
		if srcType == "" {
			srcType = "machine"
		}
		value := normalize(kf.Finding.Snippet)
		f := types.Finding{
			PatternID:      patternID,
			PatternName:    meta.Name,
			Severity:       meta.Severity,
			Category:       meta.Category,
			SourceType:     srcType,
			FilePath:       kf.Finding.Path,
			LineNumber:     kf.Finding.Line,
			ValueHash:      HashValue(value),
			ValuePreview:   maskValue(value), // redact: only a last-4 hint leaves the endpoint
			ContextLine:    "",               // never upload the surrounding line (leaks the secret)
			VerifiedActive: statusToVerified(kf.Finding.Validation.Status),
			Value:          value, // internal only (json:"-") — used for on-device validation
		}
		// Git commit provenance — populated only when Kingfisher scans history.
		if gm := kf.Finding.GitMetadata; gm != nil {
			f.CommitHash   = gm.CommitHash
			f.CommitDate   = gm.CommitDate
			f.CommitAuthor = gm.Committer.Name
			if f.CommitAuthor == "" {
				f.CommitAuthor = gm.Committer.Email
			}
		}

		// SSH/TLS: only flag the machine owner's OWN ssh keys (under ~/.ssh/).
		// Drop private-key blobs found anywhere else (caches, bundles, fixtures).
		if patternID == "ssh_private_key" {
			if !sshKeyPathRe.MatchString(kf.Finding.Path) {
				continue
			}
			has := patterns.EncryptedSSHRules[kf.Rule.ID]
			f.SSHHasPassphrase = &has
			// SSH/TLS keys have no network validator — treat presence as active.
			if f.VerifiedActive == nil {
				t := true
				f.VerifiedActive = &t
			}
		}

		findings = append(findings, f)
	}
	// Kingfisher exits non-zero when findings are present; that is not an error.
	_ = cmd.Wait()
	return findings, sc.Err()
}
