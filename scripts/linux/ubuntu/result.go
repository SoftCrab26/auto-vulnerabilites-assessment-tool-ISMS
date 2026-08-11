package main

// MitreAttack is serialized with lowercase JSON keys to match the web UI
// test_data / analyzer schema (dns_srv_*.json style).
type MitreAttack struct {
	Tactic      string   `json:"tactic"`
	Techniques  []string `json:"techniques"`
	Mitigations []string `json:"mitigations"`
}

type Status int

const (
	StatusGood Status = iota
	StatusVulnerable
	StatusInterview
	StatusManual
	StatusNotApplicable
	StatusError
)

// CheckResult is the canonical JSON array element written by linux-check.
// Field order and names match frontend/ui/test_data/*.json.
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

func (status Status) toString() string {
	switch status {
	case StatusGood:
		return "Good"
	case StatusVulnerable:
		return "Vulnerable"
	case StatusInterview:
		return "Interview"
	case StatusManual:
		return "Manual"
	case StatusNotApplicable:
		return "Not Applicable"
	case StatusError:
		return "Error"
	default:
		return "Unknown"
	}
}
