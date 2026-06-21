package main

type AWS49Input struct {
	RawData string
}

func checkAWS49(ctx ScanContext) CheckResult {
	const code = "AWS-49"
	const description = "예비 점검 항목 AWS-49 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS49Input(ctx)

	result := evalAWS49(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS49Input(ctx ScanContext) (AWS49Input, []string) {
	return AWS49Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS49(input AWS49Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-49", "implementation=stub"),
		VulnerableConfig: "",
	}
}
