package main

// MitreAttack uses lowercase JSON keys to match the web UI test_data schema.
type MitreAttack struct {
	Tactic      string   `json:"tactic"`
	Techniques  []string `json:"techniques"`
	Mitigations []string `json:"mitigations"`
}

type Status int

const (
	Good Status = iota
	Vulnerable
	Interview
	Manual
	NotApplicable
	Error
)

// CheckResult is the canonical JSON array element written by the DSM scanner.
// Field order and names match frontend/ui/test_data/*.json (and Ubuntu linux-check).
type CheckResult struct {
	RawConfig        string      `json:"RawConfig"`
	VulnerableConfig string      `json:"VulnerableConfig"`
	ErrMsg           string      `json:"ErrMsg"`
	Description      string      `json:"Description"`
	Status           Status      `json:"Status"`
	ProcessedConfig  string      `json:"ProcessedConfig"`
	MitreAttack      MitreAttack `json:"MitreAttack"`
	Code             string      `json:"Code"`
}

func (status Status) String() string {
	switch status {
	case Good:
		return "Good"
	case Vulnerable:
		return "Vulnerable"
	case Interview:
		return "Interview"
	case Manual:
		return "Manual"
	case NotApplicable:
		return "Not Applicable"
	case Error:
		return "Error"
	default:
		return "Unknown"
	}
}
