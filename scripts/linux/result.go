package main

type CheckResult struct {
	Code            string
	Description     string
	Status          Status
	RawConfig       string
	ProcessedConfig string
	ErrMsg          string
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
