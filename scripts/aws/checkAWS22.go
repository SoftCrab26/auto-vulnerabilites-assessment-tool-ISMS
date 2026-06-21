package main

type AWS22Input struct {
	RawData string
}

func checkAWS22(ctx ScanContext) CheckResult {
	const code = "AWS-22"
	const description = "3.6 NAT 게이트웨이 연결 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS22Input(ctx)

	result := evalAWS22(input)
	result.Code = code
	result.GuideCode = "3.6"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS22Input(ctx ScanContext) (AWS22Input, []string) {
	return AWS22Input{RawData: ctx.Runtime.NATGateways}, nil
}

func evalAWS22(input AWS22Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.6", "implementation=stub"),
		VulnerableConfig: "",
	}
}
