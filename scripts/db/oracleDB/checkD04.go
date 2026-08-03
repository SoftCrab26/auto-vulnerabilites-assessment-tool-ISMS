package main

import (
	"context"
	"errors"
	"strings"
)

const d04Description = "Database administrator privileges must be limited to authorized accounts."

var d04Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1098"},
	Mitigations: []string{"M1018"},
}

type D04Grant struct {
	Source    string
	Grantee   string
	Privilege string
}

type D04Input struct {
	Grants  []D04Grant
	RawRows [][]string
	LoadErr error
}

func checkD04(ctx ScanContext) CheckResult {
	result := evalD04(loadD04Input(ctx))
	result.Code = "D-04"
	result.Description = d04Description
	result.MitreAttack = d04Mitre
	return result
}

func loadD04Input(scanCtx ScanContext) D04Input {
	if scanCtx.MetadataErr != nil {
		return D04Input{LoadErr: scanCtx.MetadataErr}
	}
	// SYSBACKUP/SYSDG/SYSKM columns exist from 12c only.
	const query12c = `SELECT source_name || '|~|' || grantee || '|~|' || privilege_name
FROM (
  SELECT 'DBA_ROLE_PRIVS' source_name, grantee, granted_role privilege_name
  FROM dba_role_privs
  WHERE granted_role IN ('DBA', 'PDB_DBA')
  UNION ALL
  SELECT 'V$PWFILE_USERS', username,
         RTRIM(
           CASE WHEN sysdba = 'TRUE' THEN 'SYSDBA,' END ||
           CASE WHEN sysoper = 'TRUE' THEN 'SYSOPER,' END ||
           CASE WHEN sysasm = 'TRUE' THEN 'SYSASM,' END ||
           CASE WHEN sysbackup = 'TRUE' THEN 'SYSBACKUP,' END ||
           CASE WHEN sysdg = 'TRUE' THEN 'SYSDG,' END ||
           CASE WHEN syskm = 'TRUE' THEN 'SYSKM,' END,
           ','
         )
  FROM v$pwfile_users
)
WHERE privilege_name IS NOT NULL
ORDER BY source_name, grantee, privilege_name;`
	const query11g = `SELECT source_name || '|~|' || grantee || '|~|' || privilege_name
FROM (
  SELECT 'DBA_ROLE_PRIVS' source_name, grantee, granted_role privilege_name
  FROM dba_role_privs
  WHERE granted_role = 'DBA'
  UNION ALL
  SELECT 'V$PWFILE_USERS', username,
         RTRIM(
           CASE WHEN sysdba = 'TRUE' THEN 'SYSDBA,' END ||
           CASE WHEN sysoper = 'TRUE' THEN 'SYSOPER,' END ||
           CASE WHEN sysasm = 'TRUE' THEN 'SYSASM,' END,
           ','
         )
  FROM v$pwfile_users
)
WHERE privilege_name IS NOT NULL
ORDER BY source_name, grantee, privilege_name;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D04Input{LoadErr: err}
	}
	grants := make([]D04Grant, 0, len(rows))
	for _, row := range rows {
		if len(row) != 3 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" || strings.TrimSpace(row[2]) == "" {
			return D04Input{LoadErr: errors.New("D-04 query returned an unexpected row shape")}
		}
		grants = append(grants, D04Grant{
			Source: sanitizeEvidence(row[0]), Grantee: sanitizeEvidence(row[1]), Privilege: sanitizeEvidence(row[2]),
		})
	}
	return D04Input{Grants: grants, RawRows: rows}
}

func evalD04(input D04Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-04", d04Description, d04Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return errorResult("D-04", d04Description, d04Mitre, errors.New("D-04 administrator privilege evidence is missing"))
	}
	for _, grant := range input.Grants {
		if strings.TrimSpace(grant.Source) == "" || strings.TrimSpace(grant.Grantee) == "" || strings.TrimSpace(grant.Privilege) == "" {
			return errorResult("D-04", d04Description, d04Mitre, errors.New("D-04 administrator privilege evidence contains an empty required value"))
		}
	}
	rawConfig := formatSQLTable([]string{"SOURCE_NAME", "GRANTEE", "PRIVILEGE_NAME"}, input.RawRows)
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
}
