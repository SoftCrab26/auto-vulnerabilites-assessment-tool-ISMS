package main

type AWS04Input struct {
	RawData string
}

func checkAWS04(ctx ScanContext) CheckResult {
	const code = "AWS-04"
	const description = "1.4 IAM 그룹 사용자 계정 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS04Input(ctx)

	result := evalAWS04(input)
	result.Code = code
	result.GuideCode = "1.4"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS04Input(ctx ScanContext) (AWS04Input, []string) {
	return AWS04Input{RawData: ctx.Runtime.IAMGroups}, nil
}

func evalAWS04(input AWS04Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.4", "implementation=stub"),
		VulnerableConfig: "",
	}
}
