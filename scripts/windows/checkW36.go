package main

type W36Input struct {
	ShareAccess string
}

func checkW36(ctx ScanContext) CheckResult {
	const code = "W-36"
	const description = "Access controls on shared resources should be appropriately configured."
	mitreAttack := MitreAttack{tactic: "Lateral Movement", techniques: []string{"T1021.002"}, mitigations: []string{"M1035"}}

	input, errs := loadW36Input()
	result := evalW36(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW36Input() (W36Input, []string) {
	command := `Get-SmbShare | Sort-Object Name | ForEach-Object { $share=$_; Get-SmbShareAccess -Name $share.Name | ForEach-Object { Write-Output ($share.Name + '|' + $_.AccountName + '|' + [string]$_.AccessControlType + '|' + [string]$_.AccessRight) } }`
	results, errs := collectCommands(command)
	return W36Input{ShareAccess: firstCommandOutput(results)}, errs
}

func evalW36(input W36Input) CheckResult {
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       input.ShareAccess,
		ProcessedConfig: "shared_resource_access_control=manual_review_required",
	}
}
