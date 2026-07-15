package main

type W13Input struct {
	RawConfig string
}

func checkW13(ctx ScanContext) CheckResult {
	const code = "W-13"
	const description = "The latest applicable Windows security patches should be installed."
	mitreAttack := MitreAttack{
		tactic:      "Privilege Escalation",
		techniques:  []string{"T1068"},
		mitigations: []string{"M1051"},
	}

	input, errs := loadW13Input(ctx)
	result := evalW13(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW13Input(ctx ScanContext) (W13Input, []string) {
	commands, errs := collectCommands(
		`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object { "HOTFIX=$($_.HotFixID);INSTALLED_ON=$($_.InstalledOn.ToString('yyyy-MM-dd'));DESCRIPTION=$($_.Description)" }`,
		`$s=Get-Service -Name wuauserv -ErrorAction SilentlyContinue; if($null -eq $s){"UPDATE_SERVICE=NOT_FOUND"}else{"UPDATE_SERVICE=$($s.Status);START_TYPE=$($s.StartType)"}`,
	)
	return W13Input{RawConfig: commandOutput(commands, 0) + "\n" + commandOutput(commands, 1)}, errs
}

func evalW13(input W13Input) CheckResult {
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.RawConfig,
		ProcessedConfig: buildProcessedConfig("patch_currency=review_required"),
	}
}
