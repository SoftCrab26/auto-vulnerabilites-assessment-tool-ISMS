package main

type W32Input struct {
	Configuration string
}

func checkW32(ctx ScanContext) CheckResult {
	const code = "W-32"
	const description = "System Restore should be managed appropriately."
	mitreAttack := MitreAttack{tactic: "Impact", techniques: []string{"T1490"}, mitigations: []string{"M1053"}}

	input, errs := loadW32Input()
	result := evalW32(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW32Input() (W32Input, []string) {
	command := `$svc=Get-CimInstance Win32_Service -Filter "Name='VSS'"; Write-Output ('VSS_STATE=' + [string]$svc.State); Write-Output ('VSS_START_MODE=' + [string]$svc.StartMode); $rp=Get-ComputerRestorePoint -ErrorAction SilentlyContinue; Write-Output ('RESTORE_POINT_COUNT=' + [string](@($rp).Count)); if($rp){ Write-Output ('LATEST_RESTORE_POINT=' + [string](($rp | Sort-Object CreationTime -Descending | Select-Object -First 1).CreationTime)) }`
	results, errs := collectCommands(command)
	return W32Input{Configuration: firstCommandOutput(results)}, errs
}

func evalW32(input W32Input) CheckResult {
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.Configuration,
		ProcessedConfig: "system_restore_management=interview_required",
	}
}
