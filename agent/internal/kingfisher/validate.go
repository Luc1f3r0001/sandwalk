package kingfisher

import (
	"encoding/json"
	"os/exec"

	"sandwalk/internal/patterns"
)

type validateResult struct {
	RuleID     string `json:"rule_id"`
	IsValid    bool   `json:"is_valid"`
	StatusCode int    `json:"status_code"`
}

// ValidateValue re-validates a single secret value for the given pattern using
// `kingfisher validate`. Returns true=active, false=rotated/inactive, nil=cannot
// determine (no single-value validator, or the call failed).
func ValidateValue(patternID, value string) *bool {
	ruleID, ok := patterns.ValidationRuleFor(patternID)
	if !ok {
		return nil
	}
	out, err := exec.Command(Bin, "validate", "--rule", ruleID, value, "--format", "json").Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	var r validateResult
	if json.Unmarshal(out, &r) != nil {
		return nil
	}
	// 0 / network-failure status codes mean "couldn't reach the API" → unknown.
	if r.StatusCode == 0 {
		return nil
	}
	v := r.IsValid
	return &v
}
