package main

type AWS06Input struct {
	RawData string
}

func checkAWS06(ctx ScanContext) CheckResult {
	const code = "AWS-06"
	const description = "1.6 Key Pair 보관 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS06Input(ctx)

	result := evalAWS06(input)
	result.Code = code
	result.GuideCode = "1.6"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS06Input(ctx ScanContext) (AWS06Input, []string) {
	return AWS06Input{RawData: ctx.Runtime.KeyPairs}, nil
}

func evalAWS06(input AWS06Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.6", "implementation=stub"),
		VulnerableConfig: "",
	}
}
