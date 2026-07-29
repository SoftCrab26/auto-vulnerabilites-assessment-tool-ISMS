package main

type U20Input struct {
	Inetd auditFile
}

func checkU20(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU20(loadU20Input())
	result.Code = "U-20"
	result.Description = "/etc/inetd.conf must be owned by root and have permissions no broader than 0600."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU20Input() U20Input {
	return U20Input{Inetd: loadAuditFile("/etc/inetd.conf", false)}
}

func evalU20(input U20Input) CheckResult {
	file := input.Inetd
	if !file.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: auditFileSummary(file), ErrMsg: "required file missing: /etc/inetd.conf"}
	}
	bad := !ownerAllowed(file.Owner, "root") || !hasOnlyAllowedPermissions(file.Mode, 0600)
	status := StatusGood
	vulnerable := ""
	if bad {
		status = StatusVulnerable
		vulnerable = auditFileSummary(file)
	}
	return CheckResult{Status: status, RawConfig: auditFileSummary(file), ProcessedConfig: auditFileSummary(file), VulnerableConfig: vulnerable, ErrMsg: file.Err}
}
