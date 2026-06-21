package main

type AWS12Input struct {
	RawData string
}

func checkAWS12(ctx ScanContext) CheckResult {
	const code = "AWS-12"
	const description = "1.12 EKS 서비스 어카운트 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS12Input(ctx)

	result := evalAWS12(input)
	result.Code = code
	result.GuideCode = "1.12"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS12Input(ctx ScanContext) (AWS12Input, []string) {
	return AWS12Input{RawData: ctx.Runtime.EKSClusters}, nil
}

func evalAWS12(input AWS12Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.12", "implementation=stub"),
		VulnerableConfig: "",
	}
}
