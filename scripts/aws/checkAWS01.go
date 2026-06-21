package main

type AWS01Input struct {
	RawData string
}

func checkAWS01(ctx ScanContext) CheckResult {
	const code = "AWS-01"
	const description = "1.1 사용자 계정 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS01Input(ctx)

	result := evalAWS01(input)
	result.Code = code
	result.GuideCode = "1.1"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS01Input(ctx ScanContext) (AWS01Input, []string) {
	return AWS01Input{RawData: ctx.Runtime.IAMUsers}, nil
}

func evalAWS01(input AWS01Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.1", "implementation=stub"),
		VulnerableConfig: "",
	}
}
