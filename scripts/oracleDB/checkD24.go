package main

const d24Description = "Restrict permissions on Registry Procedures."

const (
	d24Engine    = "Oracle"
	d24Criterion = "Registry Procedures are Microsoft SQL Server features and are not available in Oracle Database"
)

var d24Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1068"},
	Mitigations: []string{"M1026"},
}

type D24Input struct {
	Engine    string
	Criterion string
}

func checkD24(ctx ScanContext) CheckResult {
	input := loadD24Input(ctx)
	result := evalD24(input)
	result.Code = "D-24"
	result.Description = d24Description
	result.MitreAttack = d24Mitre
	return result
}

func loadD24Input(_ ScanContext) D24Input {
	return D24Input{
		Engine:    d24Engine,
		Criterion: d24Criterion,
	}
}

func evalD24(input D24Input) CheckResult {
	return CheckResult{
		Status:          StatusNotApplicable,
		RawConfig:       "engine=" + sanitizeEvidence(input.Engine) + "; criterion=" + sanitizeEvidence(input.Criterion),
		ProcessedConfig: "applicability=not_applicable; reason=SQL_Server_only",
	}
}
