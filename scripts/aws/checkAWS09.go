package main

type AWS09Input struct {
	RawData string
}

func checkAWS09(ctx ScanContext) CheckResult {
	const code = "AWS-09"
	const description = "1.9 MFA (Multi-Factor Authentication) 설정"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS09Input(ctx)

	result := evalAWS09(input)
	result.Code = code
	result.GuideCode = "1.9"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS09Input(ctx ScanContext) (AWS09Input, []string) {
	return AWS09Input{RawData: ctx.Runtime.CredentialReport}, nil
}

func evalAWS09(input AWS09Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.9", "implementation=stub"),
		VulnerableConfig: "",
	}
}
