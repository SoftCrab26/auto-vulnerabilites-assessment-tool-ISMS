package main

import "time"

type Status int

const (
	Good Status = iota
	Vulnerable
	Interview
	Manual
	NotApplicable
	Error
)

type MitreAttack struct {
	Tactic      string   `json:"tactic,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	Mitigations []string `json:"mitigations,omitempty"`
}

type CheckResult struct {
	Code             string      `json:"code"`
	Description      string      `json:"description"`
	Status           Status      `json:"status"`
	RawConfig        string      `json:"rawConfig,omitempty"`
	VulnerableConfig string      `json:"vulnerableConfig,omitempty"`
	ProcessedConfig  string      `json:"processedConfig,omitempty"`
	ErrMsg           string      `json:"errMsg,omitempty"`
	MitreAttack      MitreAttack `json:"mitreAttack,omitempty"`
}

type ScanReport struct {
	OS          string        `json:"os"`
	DSM         DSMMetadata   `json:"dsm"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Results     []CheckResult `json:"results"`
	Warnings    []string      `json:"warnings,omitempty"`
}
