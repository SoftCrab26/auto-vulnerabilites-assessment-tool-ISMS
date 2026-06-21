package main

type AWS33Input struct {
	RawData string
}

func checkAWS33(ctx ScanContext) CheckResult {
	const code = "AWS-33"
	const description = "4.7 AWS 사용자 계정 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS33Input(ctx)

	result := evalAWS33(input)
	result.Code = code
	result.GuideCode = "4.7"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS33Input(ctx ScanContext) (AWS33Input, []string) {
	return AWS33Input{RawData: ctx.Runtime.CloudTrails}, nil
}

func evalAWS33(input AWS33Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.7", "implementation=stub"),
		VulnerableConfig: "",
	}
}
