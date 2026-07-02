// Package patterns holds Sandwalk's curated detector metadata (severity,
// category, blast radius, remediation) and the mapping from Kingfisher rule IDs
// to our pattern IDs. Kingfisher provides detection + validation; we keep our
// own Sandwalk-specific severity and remediation copy.
package patterns

import (
	"crypto/sha1"
	"fmt"
	"sort"
	"strings"
)

// Pattern is our curated metadata for a detector.
type Pattern struct {
	ID          string
	Name        string
	Severity    string // critical | high | medium | low
	Category    string
	BlastRadius string
	Remediation string
}

// PATTERNS — the 17 supply-chain detectors Sandwalk reports on.
var PATTERNS = map[string]Pattern{
	"aws_access_key_id": {
		ID: "aws_access_key_id", Name: "AWS Access Key ID", Severity: "high", Category: "cloud",
		BlastRadius: "Full programmatic AWS access — EC2, S3, RDS, IAM, Lambda. Attacker can exfiltrate data, spin up infra, or escalate via IAM.",
		Remediation: "1. AWS Console → IAM → Users → Security Credentials → Deactivate key.\n2. aws iam delete-access-key --access-key-id <KEY>\n3. Audit CloudTrail from key creation date.\n4. Create replacement key.",
	},
	"aws_secret_access_key": {
		ID: "aws_secret_access_key", Name: "AWS Secret Access Key", Severity: "critical", Category: "cloud",
		BlastRadius: "Full AWS API access when paired with key ID.",
		Remediation: "Rotate the key pair together via IAM console. Secret alone is useless without key ID.",
	},
	"aws_session_token": {
		ID: "aws_session_token", Name: "AWS Session Token", Severity: "high", Category: "cloud",
		BlastRadius: "Temporary STS credentials — same access as assumed IAM role. Expires ≤12h.",
		Remediation: "STS tokens expire automatically. Rotate the underlying long-lived credentials used to assume the role.",
	},
	"github_pat_classic": {
		ID: "github_pat_classic", Name: "GitHub PAT (Classic)", Severity: "high", Category: "vcs",
		BlastRadius: "Read/write to all repos the user can access. Can be used to exfiltrate code, inject backdoors, or pivot to CI/CD.",
		Remediation: "github.com/settings/tokens → Delete token. Audit GitHub audit log for recent API usage.",
	},
	"github_pat_fine_grained": {
		ID: "github_pat_fine_grained", Name: "GitHub PAT (Fine-Grained)", Severity: "high", Category: "vcs",
		BlastRadius: "Scoped to specific repos and permissions defined at token creation.",
		Remediation: "github.com/settings/tokens → Delete token.",
	},
	"github_oauth_token": {
		ID: "github_oauth_token", Name: "GitHub OAuth Token", Severity: "high", Category: "vcs",
		BlastRadius: "OAuth app scopes — repo read/write, org access per app configuration.",
		Remediation: "github.com/settings/applications → Authorized OAuth Apps → Revoke.",
	},
	"gitlab_pat": {
		ID: "gitlab_pat", Name: "GitLab Personal Access Token", Severity: "high", Category: "vcs",
		BlastRadius: "Read/write GitLab repos, CI/CD pipelines, container registry.",
		Remediation: "gitlab.com/-/profile/personal_access_tokens → Revoke token.",
	},
	"stripe_live_secret": {
		ID: "stripe_live_secret", Name: "Stripe Live Secret Key", Severity: "critical", Category: "payment",
		BlastRadius: "Full Stripe account — charge cards, issue refunds, read customer PII, create payouts to attacker bank.",
		Remediation: "dashboard.stripe.com → Developers → API Keys → Roll key immediately. Review API logs for unauthorized charges.",
	},
	"razorpay_key_id": {
		ID: "razorpay_key_id", Name: "Razorpay Key ID", Severity: "critical", Category: "payment",
		BlastRadius: "Live payment ops — create orders, capture payments, issue refunds, access customer data.",
		Remediation: "dashboard.razorpay.com → Settings → API Keys → Regenerate. Pair with new secret immediately.",
	},
	"openai_key": {
		ID: "openai_key", Name: "OpenAI API Key", Severity: "high", Category: "ai",
		BlastRadius: "Billable OpenAI usage — GPT-4, DALL-E, Whisper. Attacker runs up charges or exfiltrates prompts.",
		Remediation: "platform.openai.com/api-keys → Delete key. Check usage dashboard for unexpected spend.",
	},
	"anthropic_key": {
		ID: "anthropic_key", Name: "Anthropic API Key", Severity: "high", Category: "ai",
		BlastRadius: "Billable Anthropic API usage — Claude models.",
		Remediation: "console.anthropic.com → API Keys → Delete key.",
	},
	"google_api_key": {
		ID: "google_api_key", Name: "Google API Key", Severity: "high", Category: "cloud",
		BlastRadius: "Access to enabled Google APIs (Maps, Gemini, YouTube, etc.) — may incur billing charges.",
		Remediation: "console.cloud.google.com → APIs & Services → Credentials → Delete key or add API/IP restrictions.",
	},
	"gcp_service_account": {
		ID: "gcp_service_account", Name: "GCP Service Account Key", Severity: "critical", Category: "cloud",
		BlastRadius: "Full service account permissions — GCS, BigQuery, Compute Engine. Depends on IAM roles assigned.",
		Remediation: "console.cloud.google.com → IAM → Service Accounts → Keys → Delete key. Audit Cloud Audit Logs.",
	},
	"npm_token": {
		ID: "npm_token", Name: "npm Auth Token", Severity: "high", Category: "supply_chain",
		BlastRadius: "Publish malicious packages to npm under your org — supply chain attack affecting all downstream users.",
		Remediation: "npmjs.com → Account → Access Tokens → Delete. Audit recent publishes for tampering.",
	},
	"pypi_token": {
		ID: "pypi_token", Name: "PyPI API Token", Severity: "high", Category: "supply_chain",
		BlastRadius: "Publish malicious packages to PyPI — supply chain attack.",
		Remediation: "pypi.org/manage/account/token/ → Remove token. Audit recent releases.",
	},
	"dockerhub_pat": {
		ID: "dockerhub_pat", Name: "Docker Hub PAT", Severity: "high", Category: "supply_chain",
		BlastRadius: "Push malicious images to Docker Hub — supply chain attack via container images pulled by CI/CD pipelines.",
		Remediation: "hub.docker.com/settings/security → Personal Access Tokens → Delete. Audit recent image pushes.",
	},
	"ssh_private_key": {
		ID: "ssh_private_key", Name: "SSH / TLS Private Key", Severity: "medium", Category: "crypto",
		BlastRadius: "SSH: access to any server the key is authorized on. TLS: decrypt traffic, impersonate the server.",
		Remediation: "1. Remove public key from all ~/.ssh/authorized_keys.\n2. Generate replacement: ssh-keygen -t ed25519\n3. If TLS: revoke cert at CA, reissue, redeploy.\n4. Audit server access logs from exposure date.",
	},
}

// kingfisherRuleToPattern maps a Kingfisher rule ID to our pattern ID.
var kingfisherRuleToPattern = map[string]string{
	"kingfisher.aws.1":         "aws_access_key_id",
	"kingfisher.aws.2":         "aws_secret_access_key",
	"kingfisher.aws.4":         "aws_session_token",
	"kingfisher.github.1":      "github_pat_fine_grained",
	"kingfisher.github.2":      "github_pat_classic",
	"kingfisher.github.3":      "github_oauth_token",
	"kingfisher.gitlab.1":      "gitlab_pat",
	"kingfisher.stripe.2":      "stripe_live_secret",
	"kingfisher.razorpay.1":    "razorpay_key_id",
	"kingfisher.openai.1":      "openai_key",
	"kingfisher.openai.2":      "openai_key",
	"kingfisher.openai.3":      "openai_key",
	"kingfisher.anthropic.1":   "anthropic_key",
	"kingfisher.google.7":      "google_api_key",
	"kingfisher.gcp.1":         "gcp_service_account",
	"kingfisher.gcp.3":         "gcp_service_account",
	"kingfisher.npm.1":         "npm_token",
	"kingfisher.npm.2":         "npm_token",
	"kingfisher.pypi.1":        "pypi_token",
	"kingfisher.dockerhub.1":   "dockerhub_pat",
	"kingfisher.pem.1":         "ssh_private_key",
	"kingfisher.pem.2":         "ssh_private_key",
	"kingfisher.privkey.1":     "ssh_private_key", // encrypted (has passphrase)
	"kingfisher.privkey.2":     "ssh_private_key", // unencrypted (no passphrase)
}

// EncryptedSSHRules are the Kingfisher rule IDs that indicate a passphrase-
// protected private key. Everything else mapped to ssh_private_key is treated
// as passphrase-less (the dangerous case Sandwalk specifically flags).
var EncryptedSSHRules = map[string]bool{
	"kingfisher.privkey.1": true,
}

// PatternForRule returns our pattern ID for a Kingfisher rule ID, or "" if the
// rule is not one we report on.
func PatternForRule(ruleID string) (string, bool) {
	p, ok := kingfisherRuleToPattern[ruleID]
	return p, ok
}

// Meta returns the curated metadata for a pattern ID.
func Meta(patternID string) (Pattern, bool) {
	p, ok := PATTERNS[patternID]
	return p, ok
}

// EnabledRuleIDs returns the Kingfisher rule IDs to enable via --rule, given the
// set of pattern IDs that policy leaves enabled (empty map = all enabled).
func EnabledRuleIDs(disabled map[string]bool) []string {
	var out []string
	for ruleID, patternID := range kingfisherRuleToPattern {
		if disabled[patternID] {
			continue
		}
		out = append(out, ruleID)
	}
	return out
}

// validationRuleFor maps our pattern ID to the Kingfisher rule whose validator
// can confirm a single value. Patterns needing extra context (AWS secret needs
// the key ID; Docker Hub needs a username) or with no validator are omitted —
// those can't be re-validated from the value alone.
var validationRuleFor = map[string]string{
	"github_pat_classic":      "kingfisher.github.2",
	"github_pat_fine_grained": "kingfisher.github.1",
	"github_oauth_token":      "kingfisher.github.3",
	"gitlab_pat":              "kingfisher.gitlab.1",
	"stripe_live_secret":      "kingfisher.stripe.2",
	"razorpay_key_id":         "kingfisher.razorpay.1",
	"openai_key":              "kingfisher.openai.1",
	"anthropic_key":           "kingfisher.anthropic.1",
	"google_api_key":          "kingfisher.google.7",
	"npm_token":               "kingfisher.npm.1",
	"pypi_token":              "kingfisher.pypi.1",
}

// ValidationRuleFor returns the Kingfisher rule ID to use for single-value
// re-validation of a pattern, or ("", false) if it can't be validated alone.
func ValidationRuleFor(patternID string) (string, bool) {
	r, ok := validationRuleFor[patternID]
	return r, ok
}

// AllPatternIDs returns every pattern ID we know about.
func AllPatternIDs() []string {
	out := make([]string, 0, len(PATTERNS))
	for id := range PATTERNS {
		out = append(out, id)
	}
	return out
}

// RulesetVersion is a deterministic fingerprint of the enabled rule set. When
// policy changes which patterns are enabled, this changes — invalidating the
// manifest so the next sweep re-scans everything against the new rules.
func RulesetVersion(disabled map[string]bool) string {
	ids := EnabledRuleIDs(disabled)
	sort.Strings(ids)
	sum := sha1.Sum([]byte(strings.Join(ids, ",")))
	return fmt.Sprintf("%x", sum[:6])
}
