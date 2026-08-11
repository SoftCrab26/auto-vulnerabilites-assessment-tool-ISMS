package main

import (
	"strings"
)

type U51Input struct {
	NamedConf string
}

func checkU51(ctx ScanContext) CheckResult {
	const code = "U-51"
	const description = "DNS 동적 업데이트는 비활성화하거나 적절히 통제해야 합니다."
	mitreAttack := MitreAttack{
		Tactic:      "Impact",
		Techniques:  []string{"T1565"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU51Input()

	result := evalU51(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU51Input() (U51Input, []string) {
	files, errs := collectFiles("/etc/named.conf", "/etc/bind/named.conf")
	if len(files) == 0 {
		return U51Input{}, errs
	}
	return U51Input{NamedConf: files[0].Content}, errs
}

func evalU51(input U51Input) CheckResult {
	content := input.NamedConf
	hasDynamicUpdate := strings.Contains(content, "allow-update")

	status := StatusGood
	vulnerableConfig := ""
	if hasDynamicUpdate {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"dynamic_update=ENABLED",
			"문제점1. DNS 동적 업데이트 기능이 활성화되어 있으며 적절한 접근 통제가 필요합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("dynamic_update_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
