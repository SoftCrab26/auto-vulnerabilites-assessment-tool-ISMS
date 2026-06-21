package main

type U45Input struct {
	Mail Service
}

func checkU45(ctx ScanContext) CheckResult {
	const code = "U-45"
	const description = "Mail service version should be up to date."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1051"},
	}

	input, errs := loadU45Input(ctx)

	result := evalU45(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU45Input(ctx ScanContext) (U45Input, []string) {
	return U45Input{Mail: ctx.Services["mail"]}, nil
}

func evalU45(input U45Input) CheckResult {
	return CheckResult{
		Status:           StatusInterview,
		RawConfig:        formatServiceStatus(input.Mail),
		ProcessedConfig:  buildProcessedConfig("mail_version_check=interview"),
		VulnerableConfig: "문제점1. 메일 서비스 버전을 확인하고 최신 버전으로 유지하세요.",
	}
}
