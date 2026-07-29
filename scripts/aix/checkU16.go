package main

type U16Input struct {
	Passwd auditFile
}

func checkU16(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU16(loadU16Input())
	result.Code = "U-16"
	result.Description = "/etc/passwd must be owned by root and have permissions no broader than 0644."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003.008"}, Mitigations: []string{"M1026"}}
	return result
}

func loadU16Input() U16Input {
	return U16Input{Passwd: loadAuditFile("/etc/passwd", false)}
}

func evalU16(input U16Input) CheckResult {
	file := input.Passwd
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/passwd"}
	}
	bad := !ownerAllowed(file.Owner, "root") || !hasOnlyAllowedPermissions(file.Mode, 0644)
	status := StatusGood
	vulnerable := ""
	if bad {
		status = StatusVulnerable
		vulnerable = auditFileSummary(file)
	}
	return CheckResult{Status: status, RawConfig: auditFileSummary(file), ProcessedConfig: auditFileSummary(file), VulnerableConfig: vulnerable, ErrMsg: file.Err}
}
