package main

import (
	"context"
	"errors"
	"strings"
)

const d07Description = "Oracle database server processes must not run with root ownership."

var d07Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1068"},
	Mitigations: []string{"M1026"},
}

type D07Process struct {
	OSUser  string
	Program string
}

type D07Input struct {
	Processes []D07Process
	RawRows   [][]string
	LoadErr   error
}

func checkD07(ctx ScanContext) CheckResult {
	result := evalD07(loadD07Input(ctx))
	result.Code = "D-07"
	result.Description = d07Description
	result.MitreAttack = d07Mitre
	return result
}

func loadD07Input(scanCtx ScanContext) D07Input {
	if scanCtx.MetadataErr != nil {
		return D07Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT NVL(username, 'UNKNOWN') || '|~|' || NVL(program, 'UNKNOWN')
FROM v$process
ORDER BY username, program;`
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D07Input{LoadErr: err}
	}
	processes := make([]D07Process, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" {
			return D07Input{LoadErr: errors.New("D-07 query returned an unexpected row shape")}
		}
		processes = append(processes, D07Process{OSUser: sanitizeEvidence(row[0]), Program: sanitizeEvidence(row[1])})
	}
	return D07Input{Processes: processes, RawRows: rows}
}

func evalD07(input D07Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-07", d07Description, d07Mitre, input.LoadErr)
	}
	if len(input.Processes) == 0 {
		return errorResult("D-07", d07Description, d07Mitre, errors.New("D-07 process evidence is missing"))
	}
	var vulnerable []string
	for _, process := range input.Processes {
		osUser := strings.TrimSpace(process.OSUser)
		program := strings.TrimSpace(process.Program)
		if osUser == "" || program == "" {
			return errorResult("D-07", d07Description, d07Mitre, errors.New("D-07 process evidence contains an empty required value"))
		}
		item := "os_username=" + sanitizeEvidence(osUser) + ", program=" + sanitizeEvidence(program)
		if strings.EqualFold(osUser, "root") {
			vulnerable = append(vulnerable, item)
		}
	}
	rawConfig := formatSQLTable([]string{"USERNAME", "PROGRAM"}, input.RawRows)
	processed := formatProcessedRaw(input.RawRows)
	if len(vulnerable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        rawConfig,
			VulnerableConfig: strings.Join(vulnerable, "; "),
			ProcessedConfig:  processed,
		}
	}
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
}
