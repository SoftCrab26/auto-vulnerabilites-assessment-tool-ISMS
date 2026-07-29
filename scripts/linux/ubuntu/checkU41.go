package main

type U41Input struct {
	Automount Service
}

func checkU41(ctx ScanContext) CheckResult {
	const code = "U-41"
	const description = "Unnecessary automountd service should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU41Input(ctx)

	result := evalU41(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU41Input(ctx ScanContext) (U41Input, []string) {
	return U41Input{Automount: ctx.Services["automount"]}, nil
}

func evalU41(input U41Input) CheckResult {
	automount := input.Automount
	status := StatusGood
	vulnerableConfig := ""

	if automount.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(automount),
			"문제점1. 불필요한 automountd 서비스가 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(automount),
		ProcessedConfig:  buildProcessedConfig("automountd_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
