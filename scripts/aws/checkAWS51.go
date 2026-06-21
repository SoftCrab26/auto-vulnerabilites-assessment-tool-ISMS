package main

type AWS51Input struct {
	RawData string
}

func checkAWS51(ctx ScanContext) CheckResult {
	const code = "AWS-51"
	const description = "예비 점검 항목 AWS-51 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS51Input(ctx)

	result := evalAWS51(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS51Input(ctx ScanContext) (AWS51Input, []string) {
	return AWS51Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS51(input AWS51Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-51", "implementation=stub"),
		VulnerableConfig: "",
	}
}
