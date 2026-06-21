package main

type AWS23Input struct {
	RawData string
}

func checkAWS23(ctx ScanContext) CheckResult {
	const code = "AWS-23"
	const description = "3.7 S3 버킷/객체 접근 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS23Input(ctx)

	result := evalAWS23(input)
	result.Code = code
	result.GuideCode = "3.7"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS23Input(ctx ScanContext) (AWS23Input, []string) {
	return AWS23Input{RawData: ctx.Runtime.S3Buckets}, nil
}

func evalAWS23(input AWS23Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.7", "implementation=stub"),
		VulnerableConfig: "",
	}
}
