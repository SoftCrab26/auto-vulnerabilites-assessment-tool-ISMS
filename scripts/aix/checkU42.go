package main

type U42Input struct {
	RPC               Service
	EvidenceAvailable bool
}

func checkU42(ctx ScanContext) CheckResult {
	const code = "U-42"
	const description = "The operational need for active RPC services should be reviewed."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU42Input(ctx)
	result := evalU42(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU42Input(ctx ScanContext) (U42Input, []string) {
	return U42Input{RPC: ctx.Services["rpc"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU42(input U42Input) CheckResult {
	raw := formatServiceStatus(input.RPC)
	if input.RPC.IsActive() {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "rpc=active review_required"}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "rpc=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "rpc=inactive"}
}
