package main

type W11Input struct {
	IIS       Service
	RawConfig string
}

func checkW11(ctx ScanContext) CheckResult {
	const code = "W-11"
	const description = "IIS should run only when required and use least-privilege security settings."
	mitreAttack := MitreAttack{
		tactic:      "Privilege Escalation",
		techniques:  []string{"T1068"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadW11Input(ctx)
	result := evalW11(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW11Input(ctx ScanContext) (W11Input, []string) {
	iis := ctx.Services["iis"]
	if !iis.IsActive() {
		return W11Input{IIS: iis}, nil
	}
	commands, errs := collectCommands(
		`Import-Module WebAdministration -ErrorAction Stop; Get-ChildItem IIS:\AppPools | ForEach-Object { "POOL=$($_.Name);IDENTITY=$($_.processModel.identityType);USER=$($_.processModel.userName)" }`,
		`Import-Module WebAdministration -ErrorAction Stop; Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/* -Name enabled -PSPath IIS:\ | ForEach-Object { $_ | Out-String }`,
	)
	return W11Input{IIS: iis, RawConfig: commandOutput(commands, 0) + "\n" + commandOutput(commands, 1)}, errs
}

func evalW11(input W11Input) CheckResult {
	if !input.IIS.IsActive() {
		return CheckResult{
			Status:          StatusNotApplicable,
			ProcessedConfig: buildProcessedConfig("iis=inactive"),
		}
	}
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.RawConfig,
		ProcessedConfig: buildProcessedConfig("iis="+formatServiceStatus(input.IIS), "least_privilege=review_required"),
	}
}
