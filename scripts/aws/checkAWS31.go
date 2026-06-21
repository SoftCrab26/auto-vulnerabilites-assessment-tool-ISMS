package main

type AWS31Input struct {
	RawData string
}

func checkAWS31(ctx ScanContext) CheckResult {
	const code = "AWS-31"
	const description = "4.5 CloudTrail 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS31Input(ctx)

	result := evalAWS31(input)
	result.Code = code
	result.GuideCode = "4.5"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS31Input(ctx ScanContext) (AWS31Input, []string) {
	return AWS31Input{RawData: ctx.Runtime.CloudTrails}, nil
}

func evalAWS31(input AWS31Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.5", "implementation=stub"),
		VulnerableConfig: "",
	}
}
