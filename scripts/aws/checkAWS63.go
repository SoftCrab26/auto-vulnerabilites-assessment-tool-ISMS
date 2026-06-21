package main

type AWS63Input struct {
	RawData string
}

func checkAWS63(ctx ScanContext) CheckResult {
	const code = "AWS-63"
	const description = "예비 점검 항목 AWS-63 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS63Input(ctx)

	result := evalAWS63(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS63Input(ctx ScanContext) (AWS63Input, []string) {
	return AWS63Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS63(input AWS63Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-63", "implementation=stub"),
		VulnerableConfig: "",
	}
}
