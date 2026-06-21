package main

type AWS56Input struct {
	RawData string
}

func checkAWS56(ctx ScanContext) CheckResult {
	const code = "AWS-56"
	const description = "예비 점검 항목 AWS-56 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS56Input(ctx)

	result := evalAWS56(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS56Input(ctx ScanContext) (AWS56Input, []string) {
	return AWS56Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS56(input AWS56Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-56", "implementation=stub"),
		VulnerableConfig: "",
	}
}
