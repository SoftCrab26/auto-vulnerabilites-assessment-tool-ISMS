package main

import (
	"strings"
)

type U15Input struct {
	Passwd string
}

func checkU15(ctx ScanContext) CheckResult {
	const code = "U-15"
	const description = "No files or directories should exist without an owner (orphaned files)."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1003"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU15Input()

	result := evalU15(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU15Input() (U15Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U15Input{}, errs
	}
	return U15Input{Passwd: files[0].Content}, errs
}

func evalU15(input U15Input) CheckResult {
	// Run limited find to avoid long execution (respecting 3s timeout in run())
	findOutput := run("find / -nouser 2>/dev/null | head -20")

	status := StatusGood
	vulnerableConfig := ""

	if strings.TrimSpace(findOutput) != "" {
		status = StatusVulnerable
		lines := strings.Split(findOutput, "\n")
		sample := strings.Join(lines[:min(5, len(lines))], "\n")
		vulnerableConfig = buildVulnerableConfig(
			"orphaned_files_found=true",
			"문제점1. 소유자가 존재하지 않는 파일/디렉터리가 있습니다.\n"+sample,
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        findOutput,
		ProcessedConfig:  buildProcessedConfig("orphan_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
