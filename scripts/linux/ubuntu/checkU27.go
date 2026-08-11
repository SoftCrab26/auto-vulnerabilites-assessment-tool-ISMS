package main

import (
	"strings"
)

type U27Input struct {
	HostsEquiv string
	Rhosts     string
}

func checkU27(ctx ScanContext) CheckResult {
	const code = "U-27"
	const description = "rhosts and hosts.equiv files should be properly configured or not used."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU27Input()

	result := evalU27(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU27Input() (U27Input, []string) {
	files, errs := collectFiles("/etc/hosts.equiv", "/root/.rhosts")
	hcontent := ""
	rcontent := ""
	for _, f := range files {
		if strings.Contains(f.Path, "hosts.equiv") {
			hcontent = f.Content
		} else if strings.Contains(f.Path, "rhosts") {
			rcontent = f.Content
		}
	}
	return U27Input{HostsEquiv: hcontent, Rhosts: rcontent}, errs
}

func evalU27(input U27Input) CheckResult {
	var problems []string

	if strings.Contains(input.HostsEquiv, "+") {
		problems = append(problems, "/etc/hosts.equiv has '+' entry")
	}
	if strings.Contains(input.Rhosts, "+") {
		problems = append(problems, "~/.rhosts has '+' entry")
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. rhosts/hosts.equiv 파일에 취약한 '+' 설정이 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.HostsEquiv + "\n" + input.Rhosts,
		ProcessedConfig:  buildProcessedConfig("rhosts_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
