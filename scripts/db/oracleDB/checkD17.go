package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const d17Description = "Access to Oracle audit trail objects must be restricted to authorized principals."

var d17Mitre = MitreAttack{
	Tactic:      "Defense Evasion",
	Techniques:  []string{"T1070"},
	Mitigations: []string{"M1047"},
}

type D17Grant struct {
	Grantee   string
	Owner     string
	Object    string
	Privilege string
}

type D17Input struct {
	Grants  []D17Grant
	RawRows [][]string
	LoadErr error
}

func checkD17(ctx ScanContext) CheckResult {
	result := evalD17(loadD17Input(ctx))
	result.Code = "D-17"
	result.Description = d17Description
	result.MitreAttack = d17Mitre
	return result
}

func loadD17Input(scanCtx ScanContext) D17Input {
	if scanCtx.MetadataErr != nil {
		return D17Input{LoadErr: scanCtx.MetadataErr}
	}
	const query12c = `SELECT p.grantee || '|~|' || p.owner || '|~|' ||
       p.table_name || '|~|' || p.privilege
FROM dba_tab_privs p
LEFT JOIN dba_users u ON u.username = p.grantee
LEFT JOIN dba_roles r ON r.role = p.grantee
WHERE ((p.owner = 'SYS' AND p.table_name IN
          ('AUD$', 'FGA_LOG$', 'UNIFIED_AUDIT_TRAIL'))
       OR (p.owner = 'AUDSYS' AND p.table_name = 'AUD$UNIFIED'))
  AND (p.grantee = 'PUBLIC'
       OR NVL(u.oracle_maintained, NVL(r.oracle_maintained, 'N')) = 'N')
ORDER BY p.grantee, p.owner, p.table_name, p.privilege;`
	// 11g has no unified audit trail / AUDSYS / oracle_maintained.
	const query11g = `SELECT p.grantee || '|~|' || p.owner || '|~|' ||
       p.table_name || '|~|' || p.privilege
FROM dba_tab_privs p
LEFT JOIN dba_users u ON u.username = p.grantee
LEFT JOIN dba_roles r ON r.role = p.grantee
WHERE p.owner = 'SYS' AND p.table_name IN ('AUD$', 'FGA_LOG$')
  AND (p.grantee = 'PUBLIC' OR u.username IS NOT NULL OR r.role IS NOT NULL)
ORDER BY p.grantee, p.owner, p.table_name, p.privilege;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D17Input{LoadErr: err}
	}
	grants := make([]D17Grant, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return D17Input{LoadErr: errors.New("D-17 query returned an unexpected row shape")}
		}
		if hasBlankD17Row(row) {
			return D17Input{LoadErr: errors.New("D-17 query returned incomplete grant evidence")}
		}
		grants = append(grants, D17Grant{
			Grantee:   row[0],
			Owner:     row[1],
			Object:    row[2],
			Privilege: row[3],
		})
	}
	return D17Input{Grants: grants, RawRows: rows}
}

func hasBlankD17Row(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func evalD17(input D17Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-17", d17Description, d17Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       formatSQLTable([]string{"GRANTEE", "OWNER", "TABLE_NAME", "PRIVILEGE"}, nil),
			ProcessedConfig: formatProcessedRaw(nil),
		}
	}

	writePrivileges := map[string]bool{
		"ALTER": true, "DELETE": true, "INDEX": true, "INSERT": true,
		"REFERENCES": true, "UPDATE": true,
	}
	var risky, review []string
	for _, grant := range input.Grants {
		evidence := fmt.Sprintf("grantee=%s; object=%s.%s; privilege=%s",
			sanitizeEvidence(grant.Grantee), sanitizeEvidence(grant.Owner),
			sanitizeEvidence(grant.Object), sanitizeEvidence(grant.Privilege))
		if writePrivileges[strings.ToUpper(strings.TrimSpace(grant.Privilege))] {
			risky = append(risky, evidence)
		} else {
			review = append(review, evidence)
		}
	}
	sort.Strings(risky)
	sort.Strings(review)

	result := CheckResult{
		RawConfig:       formatSQLTable([]string{"GRANTEE", "OWNER", "TABLE_NAME", "PRIVILEGE"}, input.RawRows),
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
	if len(risky) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(risky, " | ")
		return result
	}
	result.Status = StatusManual
	return result
}
