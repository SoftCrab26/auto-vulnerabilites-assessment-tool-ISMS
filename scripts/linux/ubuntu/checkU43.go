package main

type U43Input struct {
	NIS Service
}

func checkU43(ctx ScanContext) CheckResult {
	const code = "U-43"
	const description = "NIS/NIS+ service should be disabled or NIS+ should be used if necessary."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU43Input(ctx)

	result := evalU43(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU43Input(ctx ScanContext) (U43Input, []string) {
	return U43Input{NIS: ctx.Services["nis"]}, nil
}

func evalU43(input U43Input) CheckResult {
	nis := input.NIS
	status := StatusGood
	vulnerableConfig := ""

	if nis.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(nis),
			"문제점1. NIS 서비스가 활성화되어 있습니다. NIS+ 또는 비활성화를 권장합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(nis),
		ProcessedConfig:  buildProcessedConfig("nis_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
