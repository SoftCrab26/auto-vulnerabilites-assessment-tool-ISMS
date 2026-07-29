package main

import (
	"strings"
)

type U42Input struct {
	Found []string
}

func checkU42(ctx ScanContext) CheckResult {
	const code = "U-42"
	const description = "Unnecessary RPC services should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU42Input(ctx)

	result := evalU42(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU42Input(ctx ScanContext) (U42Input, []string) {
	return U42Input{Found: activeServiceLabels(ctx.Services, "rpc")}, nil
}

func evalU42(input U42Input) CheckResult {
	status := StatusGood
	vulnerableConfig := ""
	if len(input.Found) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"rpc_services="+strings.Join(input.Found, ","),
			"문제점1. 불필요한 RPC 서비스가 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(input.Found, "\n"),
		ProcessedConfig:  buildProcessedConfig("rpc_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
