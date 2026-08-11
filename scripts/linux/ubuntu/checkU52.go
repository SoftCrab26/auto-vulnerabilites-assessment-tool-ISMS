package main

type U52Input struct {
	Telnet Service
}

func checkU52(ctx ScanContext) CheckResult {
	const code = "U-52"
	const description = "Telnet service should be disabled (use SSH instead)."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU52Input(ctx)

	result := evalU52(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU52Input(ctx ScanContext) (U52Input, []string) {
	return U52Input{Telnet: ctx.Services["telnet"]}, nil
}

func evalU52(input U52Input) CheckResult {
	telnet := input.Telnet
	status := StatusGood
	vulnerableConfig := ""

	if telnet.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(telnet),
			"문제점1. Telnet 서비스가 활성화되어 있습니다. SSH를 사용하세요.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(telnet),
		ProcessedConfig:  buildProcessedConfig("telnet_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
