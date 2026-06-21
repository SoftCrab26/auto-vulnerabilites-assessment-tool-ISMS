package main

type AWS34Input struct {
	RawData string
}

func checkAWS34(ctx ScanContext) CheckResult {
	const code = "AWS-34"
	const description = "4.8 인스턴스 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS34Input(ctx)

	result := evalAWS34(input)
	result.Code = code
	result.GuideCode = "4.8"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS34Input(ctx ScanContext) (AWS34Input, []string) {
	return AWS34Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS34(input AWS34Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.8", "implementation=stub"),
		VulnerableConfig: "",
	}
}
