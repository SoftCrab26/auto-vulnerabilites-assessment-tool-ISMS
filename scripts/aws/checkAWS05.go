package main

type AWS05Input struct {
	RawData string
}

func checkAWS05(ctx ScanContext) CheckResult {
	const code = "AWS-05"
	const description = "1.5 Key Pair 접근 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS05Input(ctx)

	result := evalAWS05(input)
	result.Code = code
	result.GuideCode = "1.5"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS05Input(ctx ScanContext) (AWS05Input, []string) {
	return AWS05Input{RawData: ctx.Runtime.KeyPairs}, nil
}

func evalAWS05(input AWS05Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.5", "implementation=stub"),
		VulnerableConfig: "",
	}
}
