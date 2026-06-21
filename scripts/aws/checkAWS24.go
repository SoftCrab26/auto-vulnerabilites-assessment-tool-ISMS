package main

type AWS24Input struct {
	RawData string
}

func checkAWS24(ctx ScanContext) CheckResult {
	const code = "AWS-24"
	const description = "3.8 RDS 서브넷 가용 영역 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS24Input(ctx)

	result := evalAWS24(input)
	result.Code = code
	result.GuideCode = "3.8"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS24Input(ctx ScanContext) (AWS24Input, []string) {
	return AWS24Input{RawData: ctx.Runtime.RDSSubnetGroups}, nil
}

func evalAWS24(input AWS24Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.8", "implementation=stub"),
		VulnerableConfig: "",
	}
}
