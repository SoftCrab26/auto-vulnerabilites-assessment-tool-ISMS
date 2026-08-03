package main

import (
	"context"
	"errors"
	"strings"
)

const d02Description = "Unnecessary database accounts must be removed or locked."

var d02Mitre = MitreAttack{
	Tactic:      "Persistence",
	Techniques:  []string{"T1078"},
	Mitigations: []string{"M1018"},
}

type D02Account struct {
	Username         string
	AccountStatus    string
	OracleMaintained string
}

type D02Input struct {
	Accounts []D02Account
	RawRows  [][]string
	LoadErr  error
}

var d02KnownDefaultAccounts = map[string]struct{}{
	"ANONYMOUS": {}, "APEX_PUBLIC_USER": {}, "BI": {}, "CTXSYS": {}, "DBSNMP": {},
	"DIP": {}, "DVF": {}, "DVSYS": {}, "EXFSYS": {}, "FLOWS_FILES": {},
	"GSMADMIN_INTERNAL": {}, "HR": {}, "IX": {}, "LBACSYS": {}, "MDDATA": {},
	"MDSYS": {}, "MGMT_VIEW": {}, "OE": {}, "OLAPSYS": {}, "ORACLE_OCM": {},
	"ORDPLUGINS": {}, "ORDSYS": {}, "OUTLN": {}, "PM": {}, "SCOTT": {},
	"SH": {}, "SI_INFORMTN_SCHEMA": {}, "SPATIAL_CSW_ADMIN_USR": {},
	"SPATIAL_WFS_ADMIN_USR": {}, "WMSYS": {}, "XDB": {}, "XS$NULL": {},
}

func checkD02(ctx ScanContext) CheckResult {
	result := evalD02(loadD02Input(ctx))
	result.Code = "D-02"
	result.Description = d02Description
	result.MitreAttack = d02Mitre
	return result
}

func loadD02Input(scanCtx ScanContext) D02Input {
	if scanCtx.MetadataErr != nil {
		return D02Input{LoadErr: scanCtx.MetadataErr}
	}
	// oracle_maintained exists only from 12c; 11g emits literal N.
	const query12c = `SELECT username || '|~|' || account_status || '|~|' || oracle_maintained
FROM dba_users
ORDER BY username;`
	const query11g = `SELECT username || '|~|' || account_status || '|~|' || 'N'
FROM dba_users
ORDER BY username;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D02Input{LoadErr: err}
	}
	accounts := make([]D02Account, 0, len(rows))
	for _, row := range rows {
		if len(row) != 3 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" || strings.TrimSpace(row[2]) == "" {
			return D02Input{LoadErr: errors.New("D-02 query returned an unexpected row shape")}
		}
		accounts = append(accounts, D02Account{
			Username:         sanitizeEvidence(row[0]),
			AccountStatus:    sanitizeEvidence(row[1]),
			OracleMaintained: sanitizeEvidence(row[2]),
		})
	}
	return D02Input{Accounts: accounts, RawRows: rows}
}

func evalD02(input D02Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-02", d02Description, d02Mitre, input.LoadErr)
	}
	if len(input.Accounts) == 0 {
		return errorResult("D-02", d02Description, d02Mitre, errors.New("D-02 account inventory is missing"))
	}

	var vulnerable []string
	for _, account := range input.Accounts {
		username := strings.ToUpper(strings.TrimSpace(account.Username))
		status := strings.ToUpper(strings.TrimSpace(account.AccountStatus))
		maintained := strings.ToUpper(strings.TrimSpace(account.OracleMaintained))
		if username == "" || status == "" || maintained == "" {
			return errorResult("D-02", d02Description, d02Mitre, errors.New("D-02 account inventory contains an empty required value"))
		}
		item := "username=" + sanitizeEvidence(username) + ", account_status=" + sanitizeEvidence(status) +
			", oracle_maintained=" + sanitizeEvidence(maintained)
		if _, known := d02KnownDefaultAccounts[username]; known && status == "OPEN" {
			vulnerable = append(vulnerable, item)
		}
	}
	rawConfig := formatSQLTable([]string{"USERNAME", "ACCOUNT_STATUS", "ORACLE_MAINTAINED"}, input.RawRows)
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
