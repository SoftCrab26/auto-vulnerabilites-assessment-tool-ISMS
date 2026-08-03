package main

import (
	"context"
	"errors"
	"strings"
)

const d06Description = "Database access must use individually assigned user accounts."

var d06Mitre = MitreAttack{
	Tactic:      "Defense Evasion",
	Techniques:  []string{"T1078"},
	Mitigations: []string{"M1018"},
}

type D06Account struct {
	Username           string
	AccountStatus      string
	LastLogin          string
	Profile            string
	AuthenticationType string
}

type D06Input struct {
	Accounts []D06Account
	RawRows  [][]string
	LoadErr  error
}

func checkD06(ctx ScanContext) CheckResult {
	result := evalD06(loadD06Input(ctx))
	result.Code = "D-06"
	result.Description = d06Description
	result.MitreAttack = d06Mitre
	return result
}

func loadD06Input(scanCtx ScanContext) D06Input {
	if scanCtx.MetadataErr != nil {
		return D06Input{LoadErr: scanCtx.MetadataErr}
	}
	// last_login exists from 12c only.
	const query12c = `SELECT username || '|~|' || account_status || '|~|' ||
       NVL(TO_CHAR(last_login, 'YYYY-MM-DD"T"HH24:MI:SS TZH:TZM'), 'NEVER') || '|~|' ||
       profile || '|~|' || authentication_type
FROM dba_users
ORDER BY username;`
	const query11g = `SELECT username || '|~|' || account_status || '|~|' ||
       'UNAVAILABLE' || '|~|' ||
       profile || '|~|' || authentication_type
FROM dba_users
ORDER BY username;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D06Input{LoadErr: err}
	}
	accounts := make([]D06Account, 0, len(rows))
	for _, row := range rows {
		if len(row) != 5 {
			return D06Input{LoadErr: errors.New("D-06 query returned an unexpected row shape")}
		}
		for _, value := range row {
			if strings.TrimSpace(value) == "" {
				return D06Input{LoadErr: errors.New("D-06 query returned an empty required value")}
			}
		}
		accounts = append(accounts, D06Account{
			Username:           sanitizeEvidence(row[0]),
			AccountStatus:      sanitizeEvidence(row[1]),
			LastLogin:          sanitizeEvidence(row[2]),
			Profile:            sanitizeEvidence(row[3]),
			AuthenticationType: sanitizeEvidence(row[4]),
		})
	}
	return D06Input{Accounts: accounts, RawRows: rows}
}

func evalD06(input D06Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-06", d06Description, d06Mitre, input.LoadErr)
	}
	if len(input.Accounts) == 0 {
		return errorResult("D-06", d06Description, d06Mitre, errors.New("D-06 account inventory is missing"))
	}
	for _, account := range input.Accounts {
		values := []string{account.Username, account.AccountStatus, account.LastLogin, account.Profile, account.AuthenticationType}
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return errorResult("D-06", d06Description, d06Mitre, errors.New("D-06 account inventory contains an empty required value"))
			}
		}
	}
	rawConfig := formatSQLTable([]string{"USERNAME", "ACCOUNT_STATUS", "LAST_LOGIN", "PROFILE", "AUTHENTICATION_TYPE"}, input.RawRows)
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
}
