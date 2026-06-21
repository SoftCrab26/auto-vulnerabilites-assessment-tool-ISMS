package main

type AWS38Input struct {
	RawData string
}

func checkAWS38(ctx ScanContext) CheckResult {
	const code = "AWS-38"
	const description = "4.12 로그 보관 기간 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS38Input(ctx)

	result := evalAWS38(input)
	result.Code = code
	result.GuideCode = "4.12"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS38Input(ctx ScanContext) (AWS38Input, []string) {
	return AWS38Input{RawData: ctx.Runtime.CloudTrails}, nil
}

func evalAWS38(input AWS38Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.12", "implementation=stub"),
		VulnerableConfig: "",
	}
}
