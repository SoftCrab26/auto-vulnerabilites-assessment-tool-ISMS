package main

type AWS11Input struct {
	RawData string
}

func checkAWS11(ctx ScanContext) CheckResult {
	const code = "AWS-11"
	const description = "1.11 EKS 사용자 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS11Input(ctx)

	result := evalAWS11(input)
	result.Code = code
	result.GuideCode = "1.11"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS11Input(ctx ScanContext) (AWS11Input, []string) {
	return AWS11Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS11(input AWS11Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.11", "implementation=stub"),
		VulnerableConfig: "",
	}
}
