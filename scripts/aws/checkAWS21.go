package main

type AWS21Input struct {
	RawData string
}

func checkAWS21(ctx ScanContext) CheckResult {
	const code = "AWS-21"
	const description = "3.5 인터넷 게이트웨이 연결 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS21Input(ctx)

	result := evalAWS21(input)
	result.Code = code
	result.GuideCode = "3.5"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS21Input(ctx ScanContext) (AWS21Input, []string) {
	return AWS21Input{RawData: ctx.Runtime.InternetGateways}, nil
}

func evalAWS21(input AWS21Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.5", "implementation=stub"),
		VulnerableConfig: "",
	}
}
