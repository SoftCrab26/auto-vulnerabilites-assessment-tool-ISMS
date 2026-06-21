package main

type AWS36Input struct {
	RawData string
}

func checkAWS36(ctx ScanContext) CheckResult {
	const code = "AWS-36"
	const description = "4.10 S3 버킷 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS36Input(ctx)

	result := evalAWS36(input)
	result.Code = code
	result.GuideCode = "4.10"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS36Input(ctx ScanContext) (AWS36Input, []string) {
	return AWS36Input{RawData: ctx.Runtime.S3Buckets}, nil
}

func evalAWS36(input AWS36Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.10", "implementation=stub"),
		VulnerableConfig: "",
	}
}
