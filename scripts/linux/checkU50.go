package main

import (
	"strings"
)

type U50Input struct {
	NamedConf string
}

func checkU50(ctx ScanContext) CheckResult {
	const code = "U-50"
	const description = "DNS Zone Transfer는 허가된 사용자에게만 허용해야 합니다."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1082"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU50Input()

	result := evalU50(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU50Input() (U50Input, []string) {
	files, errs := collectFiles("/etc/named.conf", "/etc/bind/named.conf")
	if len(files) == 0 {
		return U50Input{}, errs
	}
	return U50Input{NamedConf: files[0].Content}, errs
}

func evalU50(input U50Input) CheckResult {
	content := input.NamedConf
	hasZoneTransferControl := strings.Contains(content, "allow-transfer")

	status := StatusGood
	vulnerableConfig := ""
	if strings.TrimSpace(content) != "" && !hasZoneTransferControl {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"zone_transfer=NOT_RESTRICTED",
			"문제점1. DNS Zone Transfer가 모든 사용자에게 허용되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("zone_transfer_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
