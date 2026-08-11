package main

import (
	"strings"
)

type U59Input struct {
	SnmpdConf string
}

func checkU59(ctx ScanContext) CheckResult {
	const code = "U-59"
	const description = "SNMP should use v3 or higher if enabled."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU59Input()

	result := evalU59(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU59Input() (U59Input, []string) {
	files, errs := collectFiles("/etc/snmp/snmpd.conf", "/etc/snmpd.conf")
	if len(files) == 0 {
		return U59Input{}, errs
	}
	return U59Input{SnmpdConf: files[0].Content}, errs
}

func evalU59(input U59Input) CheckResult {
	content := input.SnmpdConf
	usesV3 := strings.Contains(content, "v3") || strings.Contains(content, "authuser") || strings.Contains(content, "createUser")

	status := StatusGood
	vulnerableConfig := ""
	if strings.TrimSpace(content) != "" && !usesV3 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"snmp_version=old",
			"문제점1. SNMP v2 이하 버전을 사용 중입니다. v3 이상을 사용하세요.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("snmp_version_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
