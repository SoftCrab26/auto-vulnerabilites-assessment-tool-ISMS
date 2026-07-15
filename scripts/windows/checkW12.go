package main

type W12Input struct {
	SQLServer Service
	RawConfig string
}

func checkW12(ctx ScanContext) CheckResult {
	const code = "W-12"
	const description = "SQL Server accounts and privileges should be securely configured."
	mitreAttack := MitreAttack{
		tactic:      "Persistence",
		techniques:  []string{"T1078.003"},
		mitigations: []string{"M1026", "M1027"},
	}

	input, errs := loadW12Input(ctx)
	result := evalW12(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW12Input(ctx ScanContext) (W12Input, []string) {
	sqlServer := ctx.Services["mssql"]
	if !sqlServer.IsActive() {
		return W12Input{SQLServer: sqlServer}, nil
	}
	commands, errs := collectCommands(
		`Get-CimInstance Win32_Service | Where-Object {$_.Name -like 'MSSQL*' -or $_.Name -like 'SQLAgent*'} | ForEach-Object { "NAME=$($_.Name);STATE=$($_.State);START_NAME=$($_.StartName);START_MODE=$($_.StartMode)" }`,
		`Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer' -ErrorAction SilentlyContinue | ForEach-Object { "LOGIN_MODE=$($_.LoginMode);AUDIT_LEVEL=$($_.AuditLevel)" }`,
	)
	return W12Input{SQLServer: sqlServer, RawConfig: commandOutput(commands, 0) + "\n" + commandOutput(commands, 1)}, errs
}

func evalW12(input W12Input) CheckResult {
	if !input.SQLServer.IsActive() {
		return CheckResult{
			Status:          StatusNotApplicable,
			ProcessedConfig: buildProcessedConfig("sql_server=inactive"),
		}
	}
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.RawConfig,
		ProcessedConfig: buildProcessedConfig("sql_server="+formatServiceStatus(input.SQLServer), "account_privileges=review_required"),
	}
}
