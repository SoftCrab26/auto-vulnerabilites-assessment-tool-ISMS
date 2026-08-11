package main

import (
	"strings"
)

type U65Input struct {
	NtpConf string
}

func checkU65(ctx ScanContext) CheckResult {
	const code = "U-65"
	const description = "NTP time synchronization should be properly configured."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1070"},
		Mitigations: []string{"M1029"},
	}

	input, errs := loadU65Input()

	result := evalU65(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU65Input() (U65Input, []string) {
	files, errs := collectFiles("/etc/ntp.conf", "/etc/chrony.conf", "/etc/chrony/chrony.conf")
	if len(files) == 0 {
		return U65Input{}, errs
	}
	return U65Input{NtpConf: files[0].Content}, errs
}

func evalU65(input U65Input) CheckResult {
	content := input.NtpConf
	hasServer := strings.Contains(content, "server ") || strings.Contains(content, "pool ")

	status := StatusGood
	vulnerableConfig := ""
	if !hasServer {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"ntp_server=NOT_FOUND",
			"문제점1. NTP 시간 동기화 설정이 되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("ntp_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
