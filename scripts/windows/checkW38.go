package main

type W38Input struct {
	RunningServices string
}

func checkW38(ctx ScanContext) CheckResult {
	const code = "W-38"
	const description = "Services should run with only the privileges required for their purpose."
	mitreAttack := MitreAttack{tactic: "Privilege Escalation", techniques: []string{"T1543.003"}, mitigations: []string{"M1042"}}

	input, errs := loadW38Input()
	result := evalW38(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW38Input() (W38Input, []string) {
	command := `Get-CimInstance Win32_Service | Where-Object State -eq 'Running' | Sort-Object Name | ForEach-Object { Write-Output ($_.Name + '|ACCOUNT=' + [string]$_.StartName + '|PATH=' + [string]$_.PathName) }`
	results, errs := collectCommands(command)
	return W38Input{RunningServices: firstCommandOutput(results)}, errs
}

func evalW38(input W38Input) CheckResult {
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.RunningServices,
		ProcessedConfig: "service_account_least_privilege=interview_required",
	}
}
