package main

import "strings"

type W40Input struct {
	SchannelSettings string
}

func checkW40(ctx ScanContext) CheckResult {
	const code = "W-40"
	const description = "Weak SCHANNEL algorithms such as RC4 and MD5 should be disabled."
	mitreAttack := MitreAttack{tactic: "Credential Access", techniques: []string{"T1557"}, mitigations: []string{"M1041"}}

	input, errs := loadW40Input()
	result := evalW40(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW40Input() (W40Input, []string) {
	command := `$base='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $targets=@(@('RC4_40_128',"$base\Ciphers\RC4 40/128"),@('RC4_56_128',"$base\Ciphers\RC4 56/128"),@('RC4_64_128',"$base\Ciphers\RC4 64/128"),@('RC4_128_128',"$base\Ciphers\RC4 128/128"),@('MD5',"$base\Hashes\MD5")); foreach($target in $targets){ if(Test-Path -LiteralPath $target[1]){ $p=Get-ItemProperty -LiteralPath $target[1]; Write-Output ($target[0] + '|PRESENT=true|ENABLED=' + [string]$p.Enabled + '|DISABLED_BY_DEFAULT=' + [string]$p.DisabledByDefault) }else{ Write-Output ($target[0] + '|PRESENT=false|ENABLED=|DISABLED_BY_DEFAULT=') } }`
	results, errs := collectCommands(command)
	return W40Input{SchannelSettings: firstCommandOutput(results)}, errs
}

func evalW40(input W40Input) CheckResult {
	lines := strings.Split(strings.TrimSpace(input.SchannelSettings), "\n")
	completeDisabled := len(lines) == 5
	var unsafe []string
	for _, line := range lines {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) != 4 || fields[1] != "PRESENT=true" {
			completeDisabled = false
			continue
		}
		enabled := strings.TrimSpace(strings.TrimPrefix(fields[2], "ENABLED="))
		disabledByDefault := strings.TrimSpace(strings.TrimPrefix(fields[3], "DISABLED_BY_DEFAULT="))
		if enabled == "0" {
			continue
		}
		completeDisabled = false
		if (enabled != "" && enabled != "0") || (enabled == "" && disabledByDefault == "0") {
			unsafe = append(unsafe, line)
		}
	}

	status := StatusInterview
	vulnerable := ""
	if len(unsafe) > 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(strings.Join(unsafe, "\n"), "RC4 or MD5 is not explicitly disabled.")
	} else if completeDisabled {
		status = StatusGood
	}
	return CheckResult{Status: status, RawConfig: input.SchannelSettings, ProcessedConfig: "rc4_md5_explicitly_disabled=" + strconvFormatBool(completeDisabled), VulnerableConfig: vulnerable}
}
