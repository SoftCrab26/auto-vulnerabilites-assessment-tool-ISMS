package main

import "strings"

type W43Input struct {
	EventLogACLs string
}

func checkW43(ctx ScanContext) CheckResult {
	const code = "W-43"
	const description = "Event log files should not grant write access to Everyone."
	mitreAttack := MitreAttack{tactic: "Defense Evasion", techniques: []string{"T1070.001", "T1222.001"}, mitigations: []string{"M1022", "M1047"}}

	input, errs := loadW43Input()
	result := evalW43(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW43Input() (W43Input, []string) {
	command := `$dir=Join-Path $env:windir 'System32\winevt\Logs'; Get-ChildItem -LiteralPath $dir -Filter '*.evtx' -File | Sort-Object FullName | ForEach-Object { $file=$_; (Get-Acl -LiteralPath $file.FullName).Access | ForEach-Object { try{$sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=[string]$_.IdentityReference}; Write-Output ($file.FullName + '|' + $sid + '|' + [string]$_.AccessControlType + '|' + [string]$_.FileSystemRights) } }`
	results, errs := collectCommands(command)
	return W43Input{EventLogACLs: firstCommandOutput(results)}, errs
}

func evalW43(input W43Input) CheckResult {
	if strings.TrimSpace(input.EventLogACLs) == "" {
		return CheckResult{Status: StatusManual, RawConfig: input.EventLogACLs, ProcessedConfig: "event_log_acl=evidence_unavailable"}
	}

	var unsafe []string
	for _, line := range strings.Split(input.EventLogACLs, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 4 || strings.TrimSpace(fields[1]) != "S-1-1-0" || !strings.EqualFold(strings.TrimSpace(fields[2]), "Allow") {
			continue
		}
		rights := strings.ToLower(fields[3])
		if containsAnyFold(rights, "fullcontrol", "modify", "write", "delete", "changepermissions", "takeownership") {
			unsafe = append(unsafe, line)
		}
	}

	if len(unsafe) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        input.EventLogACLs,
			ProcessedConfig:  "everyone_write_access=true",
			VulnerableConfig: strings.Join(unsafe, "\n"),
		}
	}
	return CheckResult{Status: StatusGood, RawConfig: input.EventLogACLs, ProcessedConfig: "everyone_write_access=false"}
}
