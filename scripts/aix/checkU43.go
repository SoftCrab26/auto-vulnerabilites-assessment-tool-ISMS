package main

type U43Input struct {
	NIS               Service
	EvidenceAvailable bool
}

func checkU43(ctx ScanContext) CheckResult {
	const code = "U-43"
	const description = "NIS services should be disabled."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU43Input(ctx)
	result := evalU43(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU43Input(ctx ScanContext) (U43Input, []string) {
	return U43Input{NIS: ctx.Services["nis"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU43(input U43Input) CheckResult {
	raw := formatServiceStatus(input.NIS)
	if input.NIS.Running {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "nis=active", VulnerableConfig: raw}
	}
	if input.NIS.Listening {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "nis=possibly_active ambiguous"}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "nis=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "nis=inactive"}
}
