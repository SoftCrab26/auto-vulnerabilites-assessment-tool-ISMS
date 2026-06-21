package main

type AWS30Input struct {
	RawData string
}

func checkAWS30(ctx ScanContext) CheckResult {
	const code = "AWS-30"
	const description = "4.4 통신구간 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS30Input(ctx)

	result := evalAWS30(input)
	result.Code = code
	result.GuideCode = "4.4"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS30Input(ctx ScanContext) (AWS30Input, []string) {
	return AWS30Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS30(input AWS30Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.4", "implementation=stub"),
		VulnerableConfig: "",
	}
}
