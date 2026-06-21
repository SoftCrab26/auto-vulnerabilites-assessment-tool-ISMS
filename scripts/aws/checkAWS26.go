package main

type AWS26Input struct {
	RawData string
}

func checkAWS26(ctx ScanContext) CheckResult {
	const code = "AWS-26"
	const description = "3.10 ELB(Elastic Load Balancing) 연결 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS26Input(ctx)

	result := evalAWS26(input)
	result.Code = code
	result.GuideCode = "3.10"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS26Input(ctx ScanContext) (AWS26Input, []string) {
	return AWS26Input{RawData: ctx.Runtime.LoadBalancers}, nil
}

func evalAWS26(input AWS26Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.10", "implementation=stub"),
		VulnerableConfig: "",
	}
}
