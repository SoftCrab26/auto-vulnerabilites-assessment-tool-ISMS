package main

type W34Input struct {
	DirectoryACLs string
}

func checkW34(ctx ScanContext) CheckResult {
	const code = "W-34"
	const description = "NTFS permissions on important directories should be appropriately restricted."
	mitreAttack := MitreAttack{tactic: "Privilege Escalation", techniques: []string{"T1222.001"}, mitigations: []string{"M1022"}}

	input, errs := loadW34Input()
	result := evalW34(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW34Input() (W34Input, []string) {
	command := `$paths=@($env:windir,(Join-Path $env:windir 'System32'),$env:ProgramFiles); foreach($path in $paths){ if(Test-Path -LiteralPath $path){ $acl=Get-Acl -LiteralPath $path; Write-Output ($path + '|OWNER=' + $acl.Owner + '|SDDL=' + $acl.Sddl) } }`
	results, errs := collectCommands(command)
	return W34Input{DirectoryACLs: firstCommandOutput(results)}, errs
}

func evalW34(input W34Input) CheckResult {
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       input.DirectoryACLs,
		ProcessedConfig: "important_directory_acl=manual_review_required",
	}
}
