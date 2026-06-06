package main

type MitreAttack struct {
	tactic      string
	techniques  []string
	mitigations []string
}
type CheckResult struct {
	Code             string
	Description      string
	Status           Status
	RawConfig        string
	VulnerableConfig string
	ProcessedConfig  string
	ErrMsg           string
	MitreAttack      MitreAttack
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
