package main

type U18Input struct {
	SecurityPasswd auditFile
}

func checkU18(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU18(loadU18Input())
	result.Code = "U-18"
	result.Description = "/etc/security/passwd must be owned by root or security and have permissions no broader than 0600."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003.008"}, Mitigations: []string{"M1026"}}
	return result
}

func loadU18Input() U18Input {
	return U18Input{SecurityPasswd: loadAuditFile("/etc/security/passwd", false)}
}

func evalU18(input U18Input) CheckResult {
	file := input.SecurityPasswd
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/security/passwd"}
	}
	bad := !ownerAllowed(file.Owner, "root", "security") || !hasOnlyAllowedPermissions(file.Mode, 0600)
	status := StatusGood
	vulnerable := ""
	if bad {
		status = StatusVulnerable
		vulnerable = auditFileSummary(file)
	}
	return CheckResult{Status: status, RawConfig: auditFileSummary(file), ProcessedConfig: auditFileSummary(file), VulnerableConfig: vulnerable, ErrMsg: file.Err}
}
