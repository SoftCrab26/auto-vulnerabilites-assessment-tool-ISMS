package main

import "strings"

type W22Input struct {
	RawConfig string
}

func checkW22(ctx ScanContext) CheckResult {
	const code = "W-22"
	const description = "SMBv1 and NetBIOS over TCP/IP should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Lateral Movement",
		techniques:  []string{"T1021.002"},
		mitigations: []string{"M1042"},
	}

	input, errs := loadW22Input(ctx)
	result := evalW22(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW22Input(ctx ScanContext) (W22Input, []string) {
	commands, errs := collectCommands(`$s=Get-SmbServerConfiguration -ErrorAction SilentlyContinue; "SMB1=$(if($null -eq $s){'UNKNOWN'}else{$s.EnableSMB1Protocol})"; $n=Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue; if($null -eq $n){"NETBIOS=UNKNOWN"}else{$n | ForEach-Object {$v=(Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions; "NETBIOS=$(if($null -eq $v){'NOT_SET'}else{$v})"}}`)
	return W22Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW22(input W22Input) CheckResult {
	smb1 := strings.ToLower(findConfigValue(input.RawConfig, "SMB1"))
	netbiosValues := []string{}
	for _, line := range strings.Split(input.RawConfig, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "NETBIOS=") {
			netbiosValues = append(netbiosValues, strings.TrimSpace(strings.TrimPrefix(line, "NETBIOS=")))
		}
	}

	status := StatusManual
	vulnerable := ""
	netbiosDisabled := len(netbiosValues) > 0
	netbiosEnabled := false
	for _, value := range netbiosValues {
		if value != "2" {
			netbiosDisabled = false
		}
		if value == "0" || value == "1" {
			netbiosEnabled = true
		}
	}
	if smb1 == "true" || netbiosEnabled {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("smb1="+smb1+" netbios="+strings.Join(netbiosValues, ","), "SMBv1 or NetBIOS over TCP/IP is enabled.")
	} else if smb1 == "false" && netbiosDisabled {
		status = StatusGood
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("smb1="+smb1, "netbios="+strings.Join(netbiosValues, ",")),
		VulnerableConfig: vulnerable,
	}
}
