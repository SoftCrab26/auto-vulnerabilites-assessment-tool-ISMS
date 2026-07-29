package main

import "time"

type Status string

const (
	StatusGood          Status = "Good"
	StatusVulnerable    Status = "Vulnerable"
	StatusInterview     Status = "Interview"
	StatusManual        Status = "Manual"
	StatusNotApplicable Status = "NotApplicable"
	StatusError         Status = "Error"
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

type DBMetadata struct {
	Name         string `json:"dbName,omitempty"`
	UniqueName   string `json:"dbUniqueName,omitempty"`
	Version      string `json:"version,omitempty"`
	DatabaseRole string `json:"databaseRole,omitempty"`
	OpenMode     string `json:"openMode,omitempty"`
}

type ScanReport struct {
	Engine      string        `json:"engine"`
	Metadata    DBMetadata    `json:"metadata"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Results     []CheckResult `json:"results"`
}
