package main

type AWS14Input struct {
	RawData string
}

func checkAWS14(ctx ScanContext) CheckResult {
	const code = "AWS-14"
	const description = "2.1 인스턴스 서비스 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS14Input(ctx)

	result := evalAWS14(input)
	result.Code = code
	result.GuideCode = "2.1"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS14Input(ctx ScanContext) (AWS14Input, []string) {
	return AWS14Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS14(input AWS14Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=2.1", "implementation=stub"),
		VulnerableConfig: "",
	}
}
