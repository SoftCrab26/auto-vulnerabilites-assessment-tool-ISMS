package main

type MitreAttack struct {
	tactic      string
	techniques  []string
	mitigations []string
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

type CheckResult struct {
	Code             string
	GuideCode        string
	Description      string
	Status           Status
	RawConfig        string
	VulnerableConfig string
	ProcessedConfig  string
	ErrMsg           string
	MitreAttack      MitreAttack
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
