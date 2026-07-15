package main

type W15Input struct {
	RawConfig string
}

func checkW15(ctx ScanContext) CheckResult {
	const code = "W-15"
	const description = "Event log size and retention settings should be appropriate."
	mitreAttack := MitreAttack{
		tactic:      "Defense Evasion",
		techniques:  []string{"T1070"},
		mitigations: []string{"M1047"},
	}

	input, errs := loadW15Input(ctx)
	result := evalW15(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW15Input(ctx ScanContext) (W15Input, []string) {
	commands, errs := collectCommands(`Get-WinEvent -ListLog Application,System,Security -ErrorAction Stop | ForEach-Object { "LOG=$($_.LogName);MAX_BYTES=$($_.MaximumSizeInBytes);MODE=$($_.LogMode);ENABLED=$($_.IsEnabled)" }`)
	return W15Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW15(input W15Input) CheckResult {
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.RawConfig,
		ProcessedConfig: buildProcessedConfig("event_log_size_retention=interview_required"),
	}
}
