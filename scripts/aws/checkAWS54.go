package main

type AWS54Input struct {
	RawData string
}

func checkAWS54(ctx ScanContext) CheckResult {
	const code = "AWS-54"
	const description = "예비 점검 항목 AWS-54 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS54Input(ctx)

	result := evalAWS54(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS54Input(ctx ScanContext) (AWS54Input, []string) {
	return AWS54Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS54(input AWS54Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-54", "implementation=stub"),
		VulnerableConfig: "",
	}
}
