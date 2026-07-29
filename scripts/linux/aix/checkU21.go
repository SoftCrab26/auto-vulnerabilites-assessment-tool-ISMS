package main

type U21Input struct {
	Syslog auditFile
}

func checkU21(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU21(loadU21Input())
	result.Code = "U-21"
	result.Description = "/etc/syslog.conf must be owned by root, bin, or sys and have permissions no broader than 0640."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU21Input() U21Input {
	return U21Input{Syslog: loadAuditFile("/etc/syslog.conf", false)}
}

func evalU21(input U21Input) CheckResult {
	file := input.Syslog
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/syslog.conf"}
	}
	bad := !ownerAllowed(file.Owner, "root", "bin", "sys") || !hasOnlyAllowedPermissions(file.Mode, 0640)
	status := StatusGood
	vulnerable := ""
	if bad {
		status = StatusVulnerable
		vulnerable = auditFileSummary(file)
	}
	return CheckResult{Status: status, RawConfig: auditFileSummary(file), ProcessedConfig: auditFileSummary(file), VulnerableConfig: vulnerable, ErrMsg: file.Err}
}
