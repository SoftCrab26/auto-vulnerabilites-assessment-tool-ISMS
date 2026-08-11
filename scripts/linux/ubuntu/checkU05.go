package main

import (
	"strings"
)

type U05Input struct {
	Passwd string
}

func checkU05(ctx ScanContext) CheckResult {
	const code = "U-05"
	const description = "No accounts other than root should have UID 0."
	mitreAttack := MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}

	input, errs := loadU05Input()

	result := evalU05(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU05Input() (U05Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U05Input{}, errs
	}
	return U05Input{Passwd: files[0].Content}, errs
}

func evalU05(input U05Input) CheckResult {
	passwdContent := input.Passwd
	var badAccounts []string

	for _, line := range strings.Split(passwdContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			username := fields[0]
			uid := strings.TrimSpace(fields[2])
			if uid == "0" && username != "root" {
				badAccounts = append(badAccounts, username)
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	processed := "uid0_check=completed"
	if len(badAccounts) > 0 {
		status = StatusVulnerable
		reason := "문제점1. root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다: " + strings.Join(badAccounts, ", ")
		vulnerableConfig = buildVulnerableConfig(
			"bad_uid0_accounts="+strings.Join(badAccounts, ","),
			reason,
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        passwdContent,
		ProcessedConfig:  buildProcessedConfig(processed, "bad_accounts="+strings.Join(badAccounts, ",")),
		VulnerableConfig: vulnerableConfig,
	}
}
