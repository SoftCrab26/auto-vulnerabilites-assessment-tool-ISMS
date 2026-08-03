package main

import (
	"context"
	"errors"
	"strings"
)

const d10Description = "Remote database access restrictions require listener, network, and host-level review."

var d10Mitre = MitreAttack{
	Tactic:      "Initial Access",
	Techniques:  []string{"T1133"},
	Mitigations: []string{"M1037"},
}

type D10Input struct {
	Parameters map[string]bool
	RawRows    [][]string
	LoadErr    error
}

func checkD10(ctx ScanContext) CheckResult {
	result := evalD10(loadD10Input(ctx))
	result.Code = "D-10"
	result.Description = d10Description
	result.MitreAttack = d10Mitre
	return result
}

func loadD10Input(scanCtx ScanContext) D10Input {
	if scanCtx.MetadataErr != nil {
		return D10Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT name || '|~|' ||
       CASE WHEN value IS NULL OR TRIM(value) IS NULL THEN 'UNSET' ELSE 'CONFIGURED' END
FROM v$parameter
WHERE name IN ('local_listener', 'remote_listener', 'listener_networks')
ORDER BY name;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D10Input{LoadErr: err}
	}
	parameters := make(map[string]bool, len(rows))
	for _, row := range rows {
		if len(row) != 2 {
			return D10Input{LoadErr: errors.New("D-10 query returned an unexpected row shape")}
		}
		name := strings.ToLower(strings.TrimSpace(row[0]))
		state := strings.ToUpper(strings.TrimSpace(row[1]))
		if state != "CONFIGURED" && state != "UNSET" {
			return D10Input{LoadErr: errors.New("D-10 query returned an unexpected parameter state")}
		}
		parameters[name] = state == "CONFIGURED"
	}
	return D10Input{Parameters: parameters, RawRows: rows}
}

func evalD10(input D10Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-10", d10Description, d10Mitre, input.LoadErr)
	}
	required := []string{"listener_networks", "local_listener", "remote_listener"}
	for _, name := range required {
		if _, ok := input.Parameters[name]; !ok {
			return errorResult("D-10", d10Description, d10Mitre, errors.New("required listener parameter evidence is missing"))
		}
	}
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       formatSQLTable([]string{"NAME", "STATE"}, input.RawRows),
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
}
