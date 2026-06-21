package main

type AWS40Input struct {
	RawData string
}

func checkAWS40(ctx ScanContext) CheckResult {
	const code = "AWS-40"
	const description = "4.14 EKS Cluster 제어 플레인 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS40Input(ctx)

	result := evalAWS40(input)
	result.Code = code
	result.GuideCode = "4.14"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS40Input(ctx ScanContext) (AWS40Input, []string) {
	return AWS40Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS40(input AWS40Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.14", "implementation=stub"),
		VulnerableConfig: "",
	}
}
