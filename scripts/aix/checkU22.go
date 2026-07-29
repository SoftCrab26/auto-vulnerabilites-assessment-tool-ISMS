package main

type U22Input struct {
	Services auditFile
}

func checkU22(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU22(loadU22Input())
	result.Code = "U-22"
	result.Description = "/etc/services must be owned by root, bin, or sys and have permissions no broader than 0644."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU22Input() U22Input {
	return U22Input{Services: loadAuditFile("/etc/services", false)}
}

func evalU22(input U22Input) CheckResult {
	file := input.Services
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/services"}
	}
	bad := !ownerAllowed(file.Owner, "root", "bin", "sys") || !hasOnlyAllowedPermissions(file.Mode, 0644)
	status := StatusGood
	vulnerable := ""
	if bad {
		status = StatusVulnerable
		vulnerable = auditFileSummary(file)
	}
	return CheckResult{Status: status, RawConfig: auditFileSummary(file), ProcessedConfig: auditFileSummary(file), VulnerableConfig: vulnerable, ErrMsg: file.Err}
}
