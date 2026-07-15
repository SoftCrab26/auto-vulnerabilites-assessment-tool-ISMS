package main

import "strings"

type W01Input struct {
	AccountConfig string
}

func checkW01(ctx ScanContext) CheckResult {
	const code = "W-01"
	const description = "The built-in Administrator account should be renamed and the Guest account should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Persistence",
		techniques:  []string{"T1078.003"},
		mitigations: []string{"M1027", "M1042"},
	}
	input, errs := loadW01Input(ctx)
	result := evalW01(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW01Input(ctx ScanContext) (W01Input, []string) {
	results, errs := collectCommands(`$admin=Get-LocalUser | Where-Object {$_.SID.Value -match '-500$'}; $guest=Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'}; "AdministratorName=$($admin.Name)"; "GuestEnabled=$($guest.Enabled)"`)
	return W01Input{AccountConfig: firstCommandOutput(results)}, errs
}

func evalW01(input W01Input) CheckResult {
	adminName := findConfigValue(input.AccountConfig, "AdministratorName")
	guestEnabled, guestKnown := parseBool(findConfigValue(input.AccountConfig, "GuestEnabled"))
	status := StatusGood
	vulnerable := ""
	if strings.EqualFold(adminName, "Administrator") || adminName == "NOT_FOUND" || !guestKnown || guestEnabled {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(
			"AdministratorName="+adminName,
			"GuestEnabled="+findConfigValue(input.AccountConfig, "GuestEnabled"),
			"The built-in Administrator account is not renamed or the Guest account is not disabled.",
		)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.AccountConfig,
		ProcessedConfig:  buildProcessedConfig("AdministratorName="+adminName, "GuestEnabled="+findConfigValue(input.AccountConfig, "GuestEnabled")),
		VulnerableConfig: vulnerable,
	}
}
