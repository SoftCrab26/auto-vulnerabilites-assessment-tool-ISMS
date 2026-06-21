package main

type AWS07Input struct {
	RawData string
}

func checkAWS07(ctx ScanContext) CheckResult {
	const code = "AWS-07"
	const description = "1.7 Admin Console 관리자 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS07Input(ctx)

	result := evalAWS07(input)
	result.Code = code
	result.GuideCode = "1.7"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS07Input(ctx ScanContext) (AWS07Input, []string) {
	return AWS07Input{RawData: ctx.Runtime.CredentialReport}, nil
}

func evalAWS07(input AWS07Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.7", "implementation=stub"),
		VulnerableConfig: "",
	}
}
