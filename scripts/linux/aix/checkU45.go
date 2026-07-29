package main

type U45Input struct {
	Mail Service
}

func checkU45(ctx ScanContext) CheckResult {
	input, errs := loadU45Input(ctx)
	result := evalU45(input)
	result.Code = "U-45"
	result.Description = "Mail service version should be up to date."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1051"}}
	return resultWithErrors(result, errs)
}

func loadU45Input(ctx ScanContext) (U45Input, []string) {
	return U45Input{Mail: ctx.Services["mail"]}, nil
}

func evalU45(input U45Input) CheckResult {
	status := StatusNotApplicable
	evidence := formatServiceStatus(input.Mail)
	processed := "mail_service=inactive"
	vulnerable := ""
	if input.Mail.IsActive() {
		status = StatusInterview
		processed = "mail_version=interview"
		vulnerable = "Verify the installed mail service version and current vendor security fixes."
	}
	return CheckResult{Status: status, RawConfig: evidence, ProcessedConfig: processed, VulnerableConfig: vulnerable}
}
