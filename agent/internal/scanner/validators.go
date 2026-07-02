package scanner

import (
	"net/http"
	"time"

	"sandwalk/internal/config"
	"sandwalk/internal/types"
)

// customValidators overrides Kingfisher's built-in validation for patterns whose
// bundled validator is unreliable. Kingfisher 1.105's Anthropic validator returns
// 404 (mapped to "inactive") for keys that are actually LIVE — so validate-or-remove
// was silently dropping real, active Anthropic secrets. Each func returns
// true=active, false=confirmed-invalid, nil=inconclusive. nil (network/rate-limit/
// unexpected status) must NEVER be treated as "dead" — we only downgrade on an
// authoritative rejection.
var customValidators = map[string]func(value string) *bool{
	"anthropic_key": anthropicActive,
}

// applyCustomValidators re-checks findings whose pattern has a custom validator,
// overriding VerifiedActive with the authoritative result. Only runs when live
// validation is enabled.
func applyCustomValidators(findings []types.Finding, cfg *config.Config) []types.Finding {
	if !cfg.Validate() {
		return findings
	}
	for i := range findings {
		if v, ok := customValidators[findings[i].PatternID]; ok && findings[i].Value != "" {
			findings[i].VerifiedActive = v(findings[i].Value)
		}
	}
	return findings
}

var validateHTTP = &http.Client{Timeout: 12 * time.Second}

// anthropicActive checks a key against the real Anthropic API. GET /v1/models is a
// read-only auth probe (no token cost): 200 = active, 401/403 = invalid, anything
// else (404/429/5xx/network) = inconclusive → nil, so a flaky endpoint can't cause
// a live key to be reported dead (the exact failure that hid a real leak).
func anthropicActive(key string) *bool {
	req, err := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := validateHTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	t, f := true, false
	switch resp.StatusCode {
	case 200:
		return &t
	case 401, 403:
		return &f
	default:
		return nil
	}
}
