package main

type AWS50Input struct {
	RawData string
}

func checkAWS50(ctx ScanContext) CheckResult {
	const code = "AWS-50"
	const description = "예비 점검 항목 AWS-50 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS50Input(ctx)

	result := evalAWS50(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS50Input(ctx ScanContext) (AWS50Input, []string) {
	return AWS50Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS50(input AWS50Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-50", "implementation=stub"),
		VulnerableConfig: "",
	}
}
