package main

type W06Input struct {
	RDPActive      bool
	AccessEvidence string
}

func checkW06(ctx ScanContext) CheckResult {
	const code = "W-06"
	const description = "Remote Desktop access should be restricted to authorized users and network sources."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1133"},
		mitigations: []string{"M1036", "M1037"},
	}
	input, errs := loadW06Input(ctx)
	result := evalW06(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW06Input(ctx ScanContext) (W06Input, []string) {
	rdp, ok := ctx.Services["rdp"]
	active := ok && rdp.IsActive()
	if !active {
		return W06Input{RDPActive: false}, nil
	}
	results, errs := collectCommands(`"RDPUsers:"; Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue | ForEach-Object {"Member=$($_.Name)|Type=$($_.ObjectClass)"}; "FirewallRules:"; Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | ForEach-Object {$f=$_ | Get-NetFirewallAddressFilter; "Rule=$($_.DisplayName)|Enabled=$($_.Enabled)|Direction=$($_.Direction)|Action=$($_.Action)|RemoteAddress=$($f.RemoteAddress -join ',')"}`)
	return W06Input{RDPActive: true, AccessEvidence: firstCommandOutput(results)}, errs
}

func evalW06(input W06Input) CheckResult {
	if !input.RDPActive {
		return CheckResult{
			Status:          StatusNotApplicable,
			ProcessedConfig: "rdp=inactive",
		}
	}
	return CheckResult{
		Status:           StatusInterview,
		RawConfig:        input.AccessEvidence,
		ProcessedConfig:  "rdp=active interview=required",
		VulnerableConfig: "Confirm that listed RDP users and permitted remote addresses are explicitly authorized.",
	}
}
