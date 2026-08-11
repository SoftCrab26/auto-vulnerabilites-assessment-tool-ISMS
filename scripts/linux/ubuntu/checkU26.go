package main

import (
	"strings"
)

type U26Input struct{}

func checkU26(ctx ScanContext) CheckResult {
	const code = "U-26"
	const description = "No non-device files should exist in /dev directory."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1036"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU26Input()

	result := evalU26(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU26Input() (U26Input, []string) {
	return U26Input{}, nil
}

func evalU26(input U26Input) CheckResult {
	// Check for regular files in /dev (should mostly be device files)
	findOutput := run("find /dev -type f 2>/dev/null | head -20")

	status := StatusGood
	vulnerableConfig := ""

	if strings.TrimSpace(findOutput) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"non_device_files_in_dev:\n"+findOutput,
			"문제점1. /dev 디렉터리에 일반 파일(디바이스 파일이 아닌)이 존재합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        findOutput,
		ProcessedConfig:  buildProcessedConfig("dev_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
