package main

type AWS13Input struct {
	RawData string
}

func checkAWS13(ctx ScanContext) CheckResult {
	const code = "AWS-13"
	const description = "1.13 EKS 불필요한 익명 접근 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS13Input(ctx)

	result := evalAWS13(input)
	result.Code = code
	result.GuideCode = "1.13"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS13Input(ctx ScanContext) (AWS13Input, []string) {
	return AWS13Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS13(input AWS13Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.13", "implementation=stub"),
		VulnerableConfig: "",
	}
}
