package main

type U36Input struct {
	RServices         Service
	InetdConfig       string
	EvidenceAvailable bool
}

func checkU36(ctx ScanContext) CheckResult {
	const code = "U-36"
	const description = "rsh, rlogin, and rexec services should be disabled."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU36Input(ctx)
	result := evalU36(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU36Input(ctx ScanContext) (U36Input, []string) {
	return U36Input{RServices: ctx.Services["rsh"], InetdConfig: ctx.Runtime.InetdConfig, EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU36(input U36Input) CheckResult {
	raw := buildLabeledRawConfig([]FileResult{{Path: "r_services", Content: formatServiceStatus(input.RServices)}, {Path: "/etc/inetd.conf", Content: input.InetdConfig}})
	if input.RServices.IsActive() {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "rsh_rlogin_rexec=active", VulnerableConfig: formatServiceStatus(input.RServices)}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "rsh_rlogin_rexec=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "rsh_rlogin_rexec=disabled"}
}
