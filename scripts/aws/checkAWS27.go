package main

type AWS27Input struct {
	RawData string
}

func checkAWS27(ctx ScanContext) CheckResult {
	const code = "AWS-27"
	const description = "4.1 EBS 및 볼륨 암호화 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS27Input(ctx)

	result := evalAWS27(input)
	result.Code = code
	result.GuideCode = "4.1"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS27Input(ctx ScanContext) (AWS27Input, []string) {
	return AWS27Input{RawData: ctx.Runtime.EBSVolumes}, nil
}

func evalAWS27(input AWS27Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=4.1", "implementation=stub"),
		VulnerableConfig: "",
	}
}
