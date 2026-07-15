package main

type W39Input struct {
	Autoruns string
}

func checkW39(ctx ScanContext) CheckResult {
	const code = "W-39"
	const description = "Unnecessary automatic startup entries should be removed."
	mitreAttack := MitreAttack{tactic: "Persistence", techniques: []string{"T1060", "T1547.001"}, mitigations: []string{"M1024"}}

	input, errs := loadW39Input()
	result := evalW39(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW39Input() (W39Input, []string) {
	command := `$keys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'); foreach($key in $keys){ if(Test-Path -LiteralPath $key){ $item=Get-ItemProperty -LiteralPath $key; foreach($property in $item.PSObject.Properties){ if($property.Name -notmatch '^PS'){ Write-Output ($key + '|' + $property.Name + '|' + [string]$property.Value) } } }; }; Get-CimInstance Win32_StartupCommand | ForEach-Object { Write-Output ('STARTUP_COMMAND|' + $_.Name + '|' + $_.Command + '|USER=' + $_.User) }`
	results, errs := collectCommands(command)
	return W39Input{Autoruns: firstCommandOutput(results)}, errs
}

func evalW39(input W39Input) CheckResult {
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       input.Autoruns,
		ProcessedConfig: "autorun_necessity=manual_review_required",
	}
}
