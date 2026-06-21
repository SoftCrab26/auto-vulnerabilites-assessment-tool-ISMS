package main

type AWS37Input struct {
	RawData string
}

func checkAWS37(ctx ScanContext) CheckResult {
	const code = "AWS-37"
	const description = "4.11 VPC 플로우 로깅 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS37Input(ctx)

	result := evalAWS37(input)
	result.Code = code
	result.GuideCode = "4.11"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS37Input(ctx ScanContext) (AWS37Input, []string) {
	return AWS37Input{RawData: ctx.Runtime.VPCFlowLogs}, nil
}

func evalAWS37(input AWS37Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.11", "implementation=stub"),
		VulnerableConfig: "",
	}
}
