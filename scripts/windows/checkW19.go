package main

import "strings"

type W19Input struct {
	ServiceActive bool
	RawConfig     string
}

func checkW19(ctx ScanContext) CheckResult {
	const code = "W-19"
	const description = "Active FTP services should apply appropriate security settings."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1133"},
		mitigations: []string{"M1037"},
	}

	input, errs := loadW19Input(ctx)
	result := evalW19(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW19Input(ctx ScanContext) (W19Input, []string) {
	active := anyServiceActive(ctx.Services, "ftp")
	if !active {
		return W19Input{ServiceActive: false}, nil
	}
	commands, errs := collectCommands(`Import-Module WebAdministration -ErrorAction SilentlyContinue; if(Get-Command Get-WebConfigurationProperty -ErrorAction SilentlyContinue){$a=Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -Name enabled -ErrorAction SilentlyContinue; "ANONYMOUS=$(if($null -eq $a){'UNKNOWN'}else{$a.Value})"}else{"ANONYMOUS=UNKNOWN"}`)
	return W19Input{ServiceActive: true, RawConfig: firstCommandOutput(commands)}, errs
}

func evalW19(input W19Input) CheckResult {
	if !input.ServiceActive {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: buildProcessedConfig("ftp=inactive")}
	}

	anonymous := strings.ToLower(findConfigValue(input.RawConfig, "ANONYMOUS"))
	status := StatusInterview
	vulnerable := ""
	if anonymous == "true" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("anonymous_authentication=true", "Active FTP permits anonymous authentication.")
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("ftp=active", "anonymous="+anonymous, "security_settings=interview_required"),
		VulnerableConfig: vulnerable,
	}
}
