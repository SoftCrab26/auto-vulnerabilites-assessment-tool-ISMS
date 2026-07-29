package main

const d16Description = "SQL Server Windows authentication mode is not applicable to Oracle Database."

var d16Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1556"},
	Mitigations: []string{"M1026"},
}

func checkD16(_ ScanContext) CheckResult {
	return CheckResult{
		Code:            "D-16",
		Description:     d16Description,
		Status:          StatusNotApplicable,
		RawConfig:       "engine=ORACLE; criterion=SQL_SERVER_ONLY",
		ProcessedConfig: "applicable=false",
		MitreAttack:     d16Mitre,
	}
}
