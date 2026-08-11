package main

type U34Input struct {
	Finger Service
}

func checkU34(ctx ScanContext) CheckResult {
	const code = "U-34"
	const description = "Finger service should be disabled."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU34Input(ctx)

	result := evalU34(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU34Input(ctx ScanContext) (U34Input, []string) {
	return U34Input{Finger: ctx.Services["finger"]}, nil
}

func evalU34(input U34Input) CheckResult {
	finger := input.Finger
	status := StatusGood
	vulnerableConfig := ""

	if finger.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(finger),
			"문제점1. Finger 서비스가 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(finger),
		ProcessedConfig:  buildProcessedConfig("finger_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
