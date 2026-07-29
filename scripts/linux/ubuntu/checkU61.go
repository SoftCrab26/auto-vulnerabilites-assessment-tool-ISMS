package main

import (
	"strings"
)

type U61Input struct {
	SnmpdConf string
}

func checkU61(ctx ScanContext) CheckResult {
	const code = "U-61"
	const description = "SNMP should have proper access control configured."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1082"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU61Input()

	result := evalU61(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU61Input() (U61Input, []string) {
	files, errs := collectFiles("/etc/snmp/snmpd.conf", "/etc/snmpd.conf")
	if len(files) == 0 {
		return U61Input{}, errs
	}
	return U61Input{SnmpdConf: files[0].Content}, errs
}

func evalU61(input U61Input) CheckResult {
	content := input.SnmpdConf
	hasAccessControl := strings.Contains(content, "rocommunity") || strings.Contains(content, "rwcommunity") || strings.Contains(content, "com2sec") || strings.Contains(content, "group")

	status := StatusGood
	vulnerableConfig := ""
	if strings.TrimSpace(content) != "" && !hasAccessControl {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"snmp_access_control=NOT_FOUND",
			"문제점1. SNMP 서비스에 접근 제어 설정이 되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("snmp_acl_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
