package main

import (
	"strings"
)

type U60Input struct {
	SnmpdConf string
}

func checkU60(ctx ScanContext) CheckResult {
	const code = "U-60"
	const description = "SNMP Community String should be complex (not public/private)."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1082"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU60Input()

	result := evalU60(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU60Input() (U60Input, []string) {
	files, errs := collectFiles("/etc/snmp/snmpd.conf", "/etc/snmpd.conf")
	if len(files) == 0 {
		return U60Input{}, errs
	}
	return U60Input{SnmpdConf: files[0].Content}, errs
}

func evalU60(input U60Input) CheckResult {
	content := input.SnmpdConf
	hasWeakCommunity := strings.Contains(content, "public") || strings.Contains(content, "private") || strings.Contains(content, "community")

	status := StatusGood
	vulnerableConfig := ""
	if hasWeakCommunity {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"snmp_community_weak=true",
			"문제점1. SNMP Community String이 기본값(public/private) 또는 취약합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("snmp_community_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
