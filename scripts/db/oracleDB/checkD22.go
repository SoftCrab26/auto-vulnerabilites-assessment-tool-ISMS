package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const d22Description = "Oracle RESOURCE_LIMIT must be TRUE so profile resource limits are enforced."

var d22Mitre = MitreAttack{
	Tactic:      "Impact",
	Techniques:  []string{"T1499"},
	Mitigations: []string{"M1037"},
}

type D22Input struct {
	ResourceLimit string
	RawRows       [][]string
	LoadErr       error
}

func checkD22(ctx ScanContext) CheckResult {
	input := loadD22Input(ctx)
	result := evalD22(input)
	result.Code = "D-22"
	result.Description = d22Description
	result.MitreAttack = d22Mitre
	return result
}

func loadD22Input(scanCtx ScanContext) D22Input {
	if scanCtx.MetadataErr != nil {
		return D22Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT name || '|~|' || value
FROM v$parameter
WHERE name = 'resource_limit';`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D22Input{LoadErr: err}
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return D22Input{LoadErr: errors.New("D-22 query did not return exactly one resource_limit row")}
	}
	if !strings.EqualFold(strings.TrimSpace(rows[0][0]), "resource_limit") {
		return D22Input{LoadErr: errors.New("D-22 query returned an unexpected parameter")}
	}
	return D22Input{ResourceLimit: strings.ToUpper(strings.TrimSpace(rows[0][1])), RawRows: rows}
}

func evalD22(input D22Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-22", d22Description, d22Mitre, input.LoadErr)
	}

	value := strings.ToUpper(strings.TrimSpace(input.ResourceLimit))
	if value == "" {
		return errorResult("D-22", d22Description, d22Mitre, errors.New("required parameter resource_limit is missing"))
	}
	result := CheckResult{
		RawConfig: formatSQLTable([]string{"NAME", "VALUE"}, input.RawRows),
	}
	processed := formatProcessedRaw(input.RawRows)
	switch value {
	case "TRUE":
		result.Status = StatusGood
		result.ProcessedConfig = processed
	case "FALSE":
		result.Status = StatusVulnerable
		result.VulnerableConfig = "resource_limit=FALSE"
		result.ProcessedConfig = processed
	default:
		return errorResult("D-22", d22Description, d22Mitre, fmt.Errorf("resource_limit returned an unsupported boolean value"))
	}
	return result
}
