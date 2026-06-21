package main

type AWS52Input struct {
	RawData string
}

func checkAWS52(ctx ScanContext) CheckResult {
	const code = "AWS-52"
	const description = "예비 점검 항목 AWS-52 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS52Input(ctx)

	result := evalAWS52(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS52Input(ctx ScanContext) (AWS52Input, []string) {
	return AWS52Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS52(input AWS52Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-52", "implementation=stub"),
		VulnerableConfig: "",
	}
}
