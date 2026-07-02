// Package config loads agent configuration and the central policy fetched from
// the API Gateway, and maps policy fields onto Kingfisher behavior.
package config

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	apiGateway      = "https://api.sandwalk.example.com"
	defaultServer   = apiGateway
	defaultDashboard = "https://sandwalk.example.com"
)

// Policy mirrors the JSON under "policies" returned by the config endpoint.
type Policy struct {
	Version                string                    `json:"version"`
	ExcludeDetectors       []string                  `json:"exclude_detectors"`
	ExcludePaths           []string                  `json:"exclude_paths"`
	VerifyCredentials      bool                      `json:"verify_credentials"`
	SSHRequireNoPassphrase bool                      `json:"ssh_require_no_passphrase"`
	GitRequireVerified     bool                      `json:"git_require_verified"`
	Patterns               map[string]patternToggle  `json:"patterns"`
}

type patternToggle struct {
	Enabled bool `json:"enabled"`
}

// configResponse is the full body from /sandwalk/config.
type configResponse struct {
	LatestVersion string `json:"latest_version"`
	NeedsUpdate   bool   `json:"needs_update"`
	DownloadURL   string `json:"download_url"`
	Policies      Policy `json:"policies"`
}

// Config is the agent's runtime configuration.
type Config struct {
	ServerURL    string // upload target (API Gateway)
	DashboardURL string // rescan / validate-all polling
	AgentKey     string

	mu     sync.RWMutex
	policy Policy
}

// Load builds a Config from the environment.
func Load() *Config {
	c := &Config{
		ServerURL:    env("SCANNER_SERVER_URL", defaultServer),
		DashboardURL: env("DASHBOARD_URL", defaultDashboard),
		AgentKey:     os.Getenv("AGENT_KEY"),
	}
	// Sensible defaults until the first policy fetch succeeds.
	c.policy = Policy{
		VerifyCredentials:      true,
		SSHRequireNoPassphrase: true,
		GitRequireVerified:     true,
	}
	return c
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// FetchPolicy queries the config endpoint and stores the policy. It also returns
// update info (latest version, needs-update, download URL) for the updater.
func (c *Config) FetchPolicy(currentVersion string) (latest string, needsUpdate bool, downloadURL string, err error) {
	req, err := http.NewRequest("GET", apiGateway+"/sandwalk/config?version="+currentVersion, nil)
	if err != nil {
		return "", false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.AgentKey)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, "", err
	}
	defer resp.Body.Close()

	var cr configResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", false, "", err
	}
	c.mu.Lock()
	c.policy = cr.Policies
	c.mu.Unlock()
	return cr.LatestVersion, cr.NeedsUpdate, cr.DownloadURL, nil
}

// ---- Policy accessors (used to drive Kingfisher) ----

// DisabledPatterns returns the set of our pattern IDs disabled by policy.
func (c *Config) DisabledPatterns() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]bool{}
	for id, tog := range c.policy.Patterns {
		if !tog.Enabled {
			out[id] = true
		}
	}
	return out
}

// ExcludePaths returns absolute path prefixes to skip during the filesystem walk.
func (c *Config) ExcludePaths() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.policy.ExcludePaths...)
}

// Validate reports whether live credential validation is enabled.
func (c *Config) Validate() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy.VerifyCredentials
}

// SSHRequireNoPassphrase reports whether passphrase-protected SSH keys should be
// dropped (only passphrase-less keys are reported).
func (c *Config) SSHRequireNoPassphrase() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy.SSHRequireNoPassphrase
}

// PolicyVersion returns the currently applied policy version.
func (c *Config) PolicyVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy.Version
}
