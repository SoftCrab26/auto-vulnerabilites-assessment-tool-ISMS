package main

import (
	"strings"
)

type U25Input struct{}

func checkU25(ctx ScanContext) CheckResult {
	const code = "U-25"
	const description = "World writable files should not exist or their reason should be known."
	mitreAttack := MitreAttack{
		tactic:      "Privilege Escalation",
		techniques:  []string{"T1222.002"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU25Input()

	result := evalU25(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU25Input() (U25Input, []string) {
	return U25Input{}, nil
}

func evalU25(input U25Input) CheckResult {
	// Limited search
	findOutput := run("find / -xdev -type f -perm -0002 2>/dev/null | head -20")

	status := StatusGood
	vulnerableConfig := ""

	if strings.TrimSpace(findOutput) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"world_writable_files:\n"+findOutput,
			"문제점1. world writable 파일이 존재합니다. 설정 이유를 확인하세요.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        findOutput,
		ProcessedConfig:  buildProcessedConfig("world_writable_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
