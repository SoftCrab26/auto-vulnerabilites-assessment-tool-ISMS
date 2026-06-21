package main

type AWS29Input struct {
	RawData string
}

func checkAWS29(ctx ScanContext) CheckResult {
	const code = "AWS-29"
	const description = "4.3 S3 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS29Input(ctx)

	result := evalAWS29(input)
	result.Code = code
	result.GuideCode = "4.3"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS29Input(ctx ScanContext) (AWS29Input, []string) {
	return AWS29Input{RawData: ctx.Runtime.S3Buckets}, nil
}

func evalAWS29(input AWS29Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.3", "implementation=stub"),
		VulnerableConfig: "",
	}
}
