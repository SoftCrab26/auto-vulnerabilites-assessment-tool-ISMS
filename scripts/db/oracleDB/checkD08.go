package main

import (
	"context"
	"errors"
	"sort"
	"strings"
)

const d08Description = "Database accounts must not retain legacy Oracle 10G password verifiers."

var d08Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1555"},
	Mitigations: []string{"M1027"},
}

type D08Account struct {
	Username         string
	PasswordVersions string
}

type D08Input struct {
	Accounts []D08Account
	RawRows  [][]string
	LoadErr  error
}

func checkD08(ctx ScanContext) CheckResult {
	result := evalD08(loadD08Input(ctx))
	result.Code = "D-08"
	result.Description = d08Description
	result.MitreAttack = d08Mitre
	return result
}

func loadD08Input(scanCtx ScanContext) D08Input {
	if scanCtx.MetadataErr != nil {
		return D08Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT username || '|~|' || NVL(password_versions, 'NONE')
FROM dba_users
ORDER BY username;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D08Input{LoadErr: err}
	}
	if len(rows) == 0 {
		return D08Input{LoadErr: errors.New("D-08 query returned no accounts")}
	}
	accounts := make([]D08Account, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" {
			return D08Input{LoadErr: errors.New("D-08 query returned an unexpected row")}
		}
		accounts = append(accounts, D08Account{
			Username:         sanitizeEvidence(row[0]),
			PasswordVersions: sanitizeEvidence(strings.ToUpper(row[1])),
		})
	}
	return D08Input{Accounts: accounts, RawRows: rows}
}

func evalD08(input D08Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-08", d08Description, d08Mitre, input.LoadErr)
	}
	if len(input.Accounts) == 0 {
		return errorResult("D-08", d08Description, d08Mitre, errors.New("password version evidence is empty"))
	}

	var legacy []string
	for _, account := range input.Accounts {
		username := sanitizeEvidence(account.Username)
		versions := sanitizeEvidence(strings.ToUpper(account.PasswordVersions))
		if username == "" || versions == "" {
			return errorResult("D-08", d08Description, d08Mitre, errors.New("account password version evidence is incomplete"))
		}
		for _, version := range strings.Fields(versions) {
			if version == "10G" {
				legacy = append(legacy, username+"=10G")
				break
			}
		}
	}
	sort.Strings(legacy)
	rawConfig := formatSQLTable([]string{"USERNAME", "PASSWORD_VERSIONS"}, input.RawRows)
	processed := formatProcessedRaw(input.RawRows)
	result := CheckResult{
		Status:          StatusGood,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
	if len(legacy) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(legacy, ", ")
	}
	return result
}
