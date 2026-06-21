package main

type AWS61Input struct {
	RawData string
}

func checkAWS61(ctx ScanContext) CheckResult {
	const code = "AWS-61"
	const description = "예비 점검 항목 AWS-61 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS61Input(ctx)

	result := evalAWS61(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS61Input(ctx ScanContext) (AWS61Input, []string) {
	return AWS61Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS61(input AWS61Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-61", "implementation=stub"),
		VulnerableConfig: "",
	}
}
