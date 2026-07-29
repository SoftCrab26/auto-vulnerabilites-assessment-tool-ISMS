package main

type U19Input struct {
	Hosts auditFile
}

func checkU19(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU19(loadU19Input())
	result.Code = "U-19"
	result.Description = "/etc/hosts must be owned by root, bin, or sys and have permissions no broader than 0644."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU19Input() U19Input {
	return U19Input{Hosts: loadAuditFile("/etc/hosts", false)}
}

func evalU19(input U19Input) CheckResult {
	file := input.Hosts
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/hosts"}
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
