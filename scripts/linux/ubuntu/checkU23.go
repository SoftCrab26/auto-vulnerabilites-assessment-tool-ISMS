package main

import (
	"strings"
)

type U23Input struct{}

func checkU23(ctx ScanContext) CheckResult {
	const code = "U-23"
	const description = "Major executables should not have SUID or SGID bit set unnecessarily."
	mitreAttack := MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548.001"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU23Input()

	result := evalU23(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU23Input() (U23Input, []string) {
	return U23Input{}, nil
}

func evalU23(input U23Input) CheckResult {
	// Limit search to avoid timeout
	findSUID := run("find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | head -30")
	findSGID := run("find /usr/bin /usr/sbin /bin /sbin -perm -2000 2>/dev/null | head -30")

	status := StatusGood
	vulnerableConfig := ""

	if strings.TrimSpace(findSUID) != "" || strings.TrimSpace(findSGID) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"SUID_files:\n"+findSUID+"\nSGID_files:\n"+findSGID,
			"문제점1. 주요 실행 파일에 SUID 또는 SGID 비트가 설정되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        findSUID + "\n" + findSGID,
		ProcessedConfig:  buildProcessedConfig("suid_sgid_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
