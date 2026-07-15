package main

type W07Input struct {
	ServiceEvidence string
}

func checkW07(ctx ScanContext) CheckResult {
	const code = "W-07"
	const description = "Unnecessary services should be stopped and disabled."
	mitreAttack := MitreAttack{
		tactic:      "Execution",
		techniques:  []string{"T1569.002"},
		mitigations: []string{"M1042"},
	}
	input, errs := loadW07Input(ctx)
	result := evalW07(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW07Input(ctx ScanContext) (W07Input, []string) {
	results, errs := collectCommands(`Get-CimInstance Win32_Service | Where-Object {$_.State -eq 'Running' -or $_.StartMode -eq 'Auto'} | Sort-Object Name | ForEach-Object {"Name=$($_.Name)|DisplayName=$($_.DisplayName)|State=$($_.State)|StartMode=$($_.StartMode)|StartName=$($_.StartName)|PathName=$($_.PathName)"}`)
	return W07Input{ServiceEvidence: firstCommandOutput(results)}, errs
}

func evalW07(input W07Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.ServiceEvidence,
		ProcessedConfig:  "manual_review=required reason=no_unnecessary_service_list_defined",
		VulnerableConfig: "Compare running and automatically started services with the approved service inventory.",
	}
}
