package main

type AWS25Input struct {
	RawData string
}

func checkAWS25(ctx ScanContext) CheckResult {
	const code = "AWS-25"
	const description = "3.9 EKS Pod 보안 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS25Input(ctx)

	result := evalAWS25(input)
	result.Code = code
	result.GuideCode = "3.9"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS25Input(ctx ScanContext) (AWS25Input, []string) {
	return AWS25Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS25(input AWS25Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.9", "implementation=stub"),
		VulnerableConfig: "",
	}
}
