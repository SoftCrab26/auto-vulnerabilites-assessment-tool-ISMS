package main

import (
	"context"
	"errors"
	"strings"
)

const d01Description = "Oracle accounts must not retain default passwords."

var d01Mitre = MitreAttack{
	Tactic:      "Initial Access",
	Techniques:  []string{"T1078"},
	Mitigations: []string{"M1027"},
}

type D01Input struct {
	Accounts []string
	LoadErr  error
}

func checkD01(ctx ScanContext) CheckResult {
	result := evalD01(loadD01Input(ctx))
	result.Code = "D-01"
	result.Description = d01Description
	result.MitreAttack = d01Mitre
	return result
}

func loadD01Input(scanCtx ScanContext) D01Input {
	if scanCtx.MetadataErr != nil {
		return D01Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT u.username || '|~|' || u.account_status
FROM dba_users_with_defpwd d
JOIN dba_users u ON u.username = d.username
ORDER BY u.username;`
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D01Input{LoadErr: err}
	}
	accounts := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != 2 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" {
			return D01Input{LoadErr: errors.New("D-01 query returned an unexpected row shape")}
		}
		accounts = append(accounts, "username="+sanitizeEvidence(row[0])+", account_status="+sanitizeEvidence(row[1]))
	}
	return D01Input{Accounts: accounts}
}

func evalD01(input D01Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-01", d01Description, d01Mitre, input.LoadErr)
	}
	if len(input.Accounts) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       "default_password_accounts=none",
			ProcessedConfig: "default_password_accounts_found=false",
		}
	}
	evidence := make([]string, len(input.Accounts))
	for i, account := range input.Accounts {
		evidence[i] = sanitizeEvidence(account)
	}
	raw := strings.Join(evidence, "; ")
	return CheckResult{
		Status:           StatusVulnerable,
		RawConfig:        raw,
		VulnerableConfig: raw,
		ProcessedConfig:  "default_password_accounts_found=true",
	}
}
