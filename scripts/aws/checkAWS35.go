package main

type AWS35Input struct {
	RawData string
}

func checkAWS35(ctx ScanContext) CheckResult {
	const code = "AWS-35"
	const description = "4.9 RDS 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS35Input(ctx)

	result := evalAWS35(input)
	result.Code = code
	result.GuideCode = "4.9"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS35Input(ctx ScanContext) (AWS35Input, []string) {
	return AWS35Input{RawData: ctx.Runtime.RDSInstances}, nil
}

func evalAWS35(input AWS35Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.9", "implementation=stub"),
		VulnerableConfig: "",
	}
}
