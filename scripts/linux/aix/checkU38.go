package main

type U38Input struct {
	Legacy            Service
	EvidenceAvailable bool
}

func checkU38(ctx ScanContext) CheckResult {
	const code = "U-38"
	const description = "echo, discard, daytime, and chargen services should be disabled."
	mitre := MitreAttack{Tactic: "Impact", Techniques: []string{"T1499"}, Mitigations: []string{"M1022"}}
	input, errs := loadU38Input(ctx)
	result := evalU38(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU38Input(ctx ScanContext) (U38Input, []string) {
	return U38Input{Legacy: ctx.Services["dos"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU38(input U38Input) CheckResult {
	raw := formatServiceStatus(input.Legacy)
	if input.Legacy.IsActive() {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "echo_discard_daytime_chargen=active", VulnerableConfig: raw}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "echo_discard_daytime_chargen=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "echo_discard_daytime_chargen=disabled"}
}
