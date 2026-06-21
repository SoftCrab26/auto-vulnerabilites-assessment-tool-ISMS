package main

type AWS32Input struct {
	RawData string
}

func checkAWS32(ctx ScanContext) CheckResult {
	const code = "AWS-32"
	const description = "4.6 CloudWatch 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS32Input(ctx)

	result := evalAWS32(input)
	result.Code = code
	result.GuideCode = "4.6"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS32Input(ctx ScanContext) (AWS32Input, []string) {
	return AWS32Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS32(input AWS32Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.6", "implementation=stub"),
		VulnerableConfig: "",
	}
}
