package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const d19Description = "OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES must all be FALSE. The guide's REMOTE_OS_AUTHENTICATION label maps to Oracle parameter REMOTE_OS_AUTHENT."

var d19Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1078"},
	Mitigations: []string{"M1026"},
}

type D19Input struct {
	Parameters map[string]string
	LoadErr    error
}

func checkD19(ctx ScanContext) CheckResult {
	input := loadD19Input(ctx)
	result := evalD19(input)
	result.Code = "D-19"
	result.Description = d19Description
	result.MitreAttack = d19Mitre
	return result
}

func loadD19Input(scanCtx ScanContext) D19Input {
	if scanCtx.MetadataErr != nil {
		return D19Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT name || '|~|' || value
FROM v$parameter
WHERE name IN ('os_roles', 'remote_os_authent', 'remote_os_roles')
ORDER BY name;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D19Input{LoadErr: err}
	}
	parameters := make(map[string]string, len(rows))
	for _, row := range rows {
		if len(row) != 2 {
			return D19Input{LoadErr: errors.New("D-19 query returned an unexpected row shape")}
		}
		name := strings.ToLower(strings.TrimSpace(row[0]))
		if _, exists := parameters[name]; exists {
			return D19Input{LoadErr: fmt.Errorf("D-19 query returned duplicate parameter %s", sanitizeEvidence(name))}
		}
		parameters[name] = strings.ToUpper(strings.TrimSpace(row[1]))
	}
	return D19Input{Parameters: parameters}
}

func evalD19(input D19Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-19", d19Description, d19Mitre, input.LoadErr)
	}

	required := []string{"os_roles", "remote_os_authent", "remote_os_roles"}
	var evidence, vulnerable []string
	for _, name := range required {
		value, ok := input.Parameters[name]
		if !ok || value == "" {
			return errorResult("D-19", d19Description, d19Mitre, fmt.Errorf("required parameter %s is missing", name))
		}
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "TRUE" && value != "FALSE" {
			return errorResult("D-19", d19Description, d19Mitre, fmt.Errorf("parameter %s returned an unsupported boolean value", name))
		}
		evidence = append(evidence, name+"="+value)
		if value == "TRUE" {
			vulnerable = append(vulnerable, name+"=TRUE")
		}
	}
	sort.Strings(evidence)
	sort.Strings(vulnerable)

	result := CheckResult{
		Status:          StatusGood,
		RawConfig:       strings.Join(evidence, ", "),
		ProcessedConfig: "all_required_parameters_present=true; all_false=true",
	}
	if len(vulnerable) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(vulnerable, ", ")
		result.ProcessedConfig = "all_required_parameters_present=true; all_false=false"
	}
	return result
}
