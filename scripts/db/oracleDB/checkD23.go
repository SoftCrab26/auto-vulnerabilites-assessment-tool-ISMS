package main

const d23Description = "Restrict use of xp_cmdshell."

const (
	d23Engine    = "Oracle"
	d23Criterion = "xp_cmdshell is a Microsoft SQL Server feature and is not available in Oracle Database"
)

var d23Mitre = MitreAttack{
	Tactic:      "Execution",
	Techniques:  []string{"T1059"},
	Mitigations: []string{"M1042"},
}

type D23Input struct {
	Engine    string
	Criterion string
}

func checkD23(ctx ScanContext) CheckResult {
	input := loadD23Input(ctx)
	result := evalD23(input)
	result.Code = "D-23"
	result.Description = d23Description
	result.MitreAttack = d23Mitre
	return result
}

func loadD23Input(_ ScanContext) D23Input {
	return D23Input{
		Engine:    d23Engine,
		Criterion: d23Criterion,
	}
}

func evalD23(input D23Input) CheckResult {
	rawConfig := "engine=" + sanitizeEvidence(input.Engine) + "; criterion=" + sanitizeEvidence(input.Criterion)
	return CheckResult{
		Status:          StatusNotApplicable,
		RawConfig:       rawConfig,
		ProcessedConfig: rawConfig,
	}
}
