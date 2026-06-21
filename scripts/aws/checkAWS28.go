package main

type AWS28Input struct {
	RawData string
}

func checkAWS28(ctx ScanContext) CheckResult {
	const code = "AWS-28"
	const description = "4.2 RDS 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS28Input(ctx)

	result := evalAWS28(input)
	result.Code = code
	result.GuideCode = "4.2"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS28Input(ctx ScanContext) (AWS28Input, []string) {
	return AWS28Input{RawData: ctx.Runtime.RDSInstances}, nil
}

func evalAWS28(input AWS28Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.2", "implementation=stub"),
		VulnerableConfig: "",
	}
}
