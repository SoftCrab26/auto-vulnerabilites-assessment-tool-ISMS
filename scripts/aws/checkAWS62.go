package main

type AWS62Input struct {
	RawData string
}

func checkAWS62(ctx ScanContext) CheckResult {
	const code = "AWS-62"
	const description = "예비 점검 항목 AWS-62 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS62Input(ctx)

	result := evalAWS62(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS62Input(ctx ScanContext) (AWS62Input, []string) {
	return AWS62Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS62(input AWS62Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-62", "implementation=stub"),
		VulnerableConfig: "",
	}
}
