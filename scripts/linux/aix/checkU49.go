package main

type U49Input struct {
	DNS Service
}

func checkU49(ctx ScanContext) CheckResult {
	input, errs := loadU49Input(ctx)
	result := evalU49(input)
	result.Code = "U-49"
	result.Description = "DNS service version should have current security fixes."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1051"}}
	return resultWithErrors(result, errs)
}

func loadU49Input(ctx ScanContext) (U49Input, []string) {
	return U49Input{DNS: ctx.Services["dns"]}, nil
}

func evalU49(input U49Input) CheckResult {
	status := StatusNotApplicable
	evidence := formatServiceStatus(input.DNS)
	processed := "dns_service=inactive"
	vulnerable := ""
	if input.DNS.IsActive() {
		status = StatusInterview
		processed = "dns_version=interview"
		vulnerable = "Verify the installed DNS version and current vendor security fixes."
	}
	return CheckResult{Status: status, RawConfig: evidence, ProcessedConfig: processed, VulnerableConfig: vulnerable}
}
