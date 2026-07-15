package main

import "strings"

type W37Input struct {
	RegistryACLs string
}

func checkW37(ctx ScanContext) CheckResult {
	const code = "W-37"
	const description = "Access to important registry keys should be restricted from Everyone and standard Users."
	mitreAttack := MitreAttack{tactic: "Privilege Escalation", techniques: []string{"T1112"}, mitigations: []string{"M1022"}}

	input, errs := loadW37Input()
	result := evalW37(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW37Input() (W37Input, []string) {
	command := `$paths=@('Registry::HKEY_LOCAL_MACHINE\SAM','Registry::HKEY_LOCAL_MACHINE\SECURITY','Registry::HKEY_LOCAL_MACHINE\SYSTEM'); foreach($path in $paths){ if(Test-Path -LiteralPath $path){ (Get-Acl -LiteralPath $path).Access | ForEach-Object { try{$sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=[string]$_.IdentityReference}; Write-Output ($path + '|' + $sid + '|' + [string]$_.AccessControlType + '|' + [string]$_.RegistryRights) } } }`
	results, errs := collectCommands(command)
	return W37Input{RegistryACLs: firstCommandOutput(results)}, errs
}

func evalW37(input W37Input) CheckResult {
	var unsafe []string
	for _, line := range strings.Split(input.RegistryACLs, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 4 || !strings.EqualFold(strings.TrimSpace(fields[2]), "Allow") {
			continue
		}
		sid := strings.TrimSpace(fields[1])
		rights := strings.ToLower(fields[3])
		broadPrincipal := sid == "S-1-1-0" || sid == "S-1-5-32-545"
		writeAccess := containsAnyFold(rights, "fullcontrol", "writekey", "setvalue", "createsubkey", "changepermissions", "takeownership")
		if broadPrincipal && writeAccess {
			unsafe = append(unsafe, line)
		}
	}

	status := StatusManual
	vulnerable := ""
	if len(unsafe) > 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(strings.Join(unsafe, "\n"), "Everyone or Users has write-capable access on a sampled important registry key.")
	}
	return CheckResult{Status: status, RawConfig: input.RegistryACLs, ProcessedConfig: "important_registry_target_scope=manual_review_required", VulnerableConfig: vulnerable}
}
