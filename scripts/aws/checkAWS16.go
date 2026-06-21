package main

type AWS16Input struct {
	RawData string
}

func checkAWS16(ctx ScanContext) CheckResult {
	const code = "AWS-16"
	const description = "2.3 기타 서비스 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS16Input(ctx)

	result := evalAWS16(input)
	result.Code = code
	result.GuideCode = "2.3"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS16Input(ctx ScanContext) (AWS16Input, []string) {
	return AWS16Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS16(input AWS16Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=2.3", "implementation=stub"),
		VulnerableConfig: "",
	}
}
