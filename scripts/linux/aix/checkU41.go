package main

type U41Input struct {
	Automount         Service
	EvidenceAvailable bool
}

func checkU41(ctx ScanContext) CheckResult {
	const code = "U-41"
	const description = "The operational need for active automount services should be reviewed."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU41Input(ctx)
	result := evalU41(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU41Input(ctx ScanContext) (U41Input, []string) {
	return U41Input{Automount: ctx.Services["automount"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU41(input U41Input) CheckResult {
	raw := formatServiceStatus(input.Automount)
	if input.Automount.IsActive() {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "automount=active review_required"}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "automount=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "automount=inactive"}
}
