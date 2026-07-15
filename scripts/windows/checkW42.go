package main

import "strings"

type W42Input struct {
	AuditPolicy string
}

func checkW42(ctx ScanContext) CheckResult {
	const code = "W-42"
	const description = "Audit policy should be enabled for important event categories."
	mitreAttack := MitreAttack{tactic: "Defense Evasion", techniques: []string{"T1562.002"}, mitigations: []string{"M1047"}}

	input, errs := loadW42Input()
	result := evalW42(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW42Input() (W42Input, []string) {
	command := `& auditpol.exe /get /category:* /r | ForEach-Object { Write-Output $_ }`
	results, errs := collectCommands(command)
	return W42Input{AuditPolicy: firstCommandOutput(results)}, errs
}

func evalW42(input W42Input) CheckResult {
	raw := strings.TrimSpace(input.AuditPolicy)
	status := StatusInterview
	vulnerable := ""
	if raw != "" {
		lower := strings.ToLower(raw)
		hasEnabledSetting := strings.Contains(lower, "success") || strings.Contains(lower, "failure") || strings.Contains(raw, "성공") || strings.Contains(raw, "실패")
		if !hasEnabledSetting && (strings.Contains(lower, "no auditing") || strings.Contains(raw, "감사 안 함")) {
			status = StatusVulnerable
			vulnerable = "All returned audit policy settings appear disabled."
		}
	}
	return CheckResult{Status: status, RawConfig: input.AuditPolicy, ProcessedConfig: "important_audit_categories=interview_required", VulnerableConfig: vulnerable}
}
