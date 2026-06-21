package main

type AWS03Input struct {
	RawData string
}

func checkAWS03(ctx ScanContext) CheckResult {
	const code = "AWS-03"
	const description = "1.3 IAM 사용자 계정 식별 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS03Input(ctx)

	result := evalAWS03(input)
	result.Code = code
	result.GuideCode = "1.3"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS03Input(ctx ScanContext) (AWS03Input, []string) {
	return AWS03Input{RawData: ctx.Runtime.IAMUsers}, nil
}

func evalAWS03(input AWS03Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.3", "implementation=stub"),
		VulnerableConfig: "",
	}
}
