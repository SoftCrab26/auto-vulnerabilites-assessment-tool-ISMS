package main

type AWS39Input struct {
	RawData string
}

func checkAWS39(ctx ScanContext) CheckResult {
	const code = "AWS-39"
	const description = "4.13 백업 사용 여부"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS39Input(ctx)

	result := evalAWS39(input)
	result.Code = code
	result.GuideCode = "4.13"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS39Input(ctx ScanContext) (AWS39Input, []string) {
	return AWS39Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS39(input AWS39Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.13", "implementation=stub"),
		VulnerableConfig: "",
	}
}
