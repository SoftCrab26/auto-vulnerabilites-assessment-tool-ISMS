package main

type AWS41Input struct {
	RawData string
}

func checkAWS41(ctx ScanContext) CheckResult {
	const code = "AWS-41"
	const description = "4.15 EKS Cluster 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS41Input(ctx)

	result := evalAWS41(input)
	result.Code = code
	result.GuideCode = "4.15"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS41Input(ctx ScanContext) (AWS41Input, []string) {
	return AWS41Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS41(input AWS41Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.15", "implementation=stub"),
		VulnerableConfig: "",
	}
}
