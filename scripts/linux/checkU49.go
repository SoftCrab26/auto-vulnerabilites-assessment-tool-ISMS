package main

type U49Input struct {
	DNS Service
}

func checkU49(ctx ScanContext) CheckResult {
	const code = "U-49"
	const description = "DNS 보안 버전 패치를 주기적으로 적용해야 합니다."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1051"},
	}

	input, errs := loadU49Input(ctx)

	result := evalU49(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU49Input(ctx ScanContext) (U49Input, []string) {
	return U49Input{DNS: ctx.Services["dns"]}, nil
}

func evalU49(input U49Input) CheckResult {
	return CheckResult{
		Status:           StatusInterview,
		RawConfig:        formatServiceStatus(input.DNS),
		ProcessedConfig:  buildProcessedConfig("dns_patch_check=interview"),
		VulnerableConfig: "문제점1. DNS 보안 패치 적용 여부를 수동으로 확인해야 합니다.",
	}
}
