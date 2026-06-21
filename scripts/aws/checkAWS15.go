package main

type AWS15Input struct {
	RawData string
}

func checkAWS15(ctx ScanContext) CheckResult {
	const code = "AWS-15"
	const description = "2.2 네트워크 서비스 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS15Input(ctx)

	result := evalAWS15(input)
	result.Code = code
	result.GuideCode = "2.2"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS15Input(ctx ScanContext) (AWS15Input, []string) {
	return AWS15Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS15(input AWS15Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=2.2", "implementation=stub"),
		VulnerableConfig: "",
	}
}
