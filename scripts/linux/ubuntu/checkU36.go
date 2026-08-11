package main

import (
	"strings"
)

type U36Input struct {
	Found []string
}

func checkU36(ctx ScanContext) CheckResult {
	const code = "U-36"
	const description = "Unnecessary r-series services (rsh, rlogin, rexec) should be disabled."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU36Input(ctx)

	result := evalU36(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU36Input(ctx ScanContext) (U36Input, []string) {
	return U36Input{Found: activeServiceLabels(ctx.Services, "rsh")}, nil
}

func evalU36(input U36Input) CheckResult {
	status := StatusGood
	vulnerableConfig := ""
	if len(input.Found) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"r_services_running="+strings.Join(input.Found, ","),
			"문제점1. 불필요한 r 계열 서비스가 활성화되어 있습니다: "+strings.Join(input.Found, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(input.Found, "\n"),
		ProcessedConfig:  buildProcessedConfig("r_services_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
