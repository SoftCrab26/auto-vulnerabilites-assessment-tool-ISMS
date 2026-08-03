package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const d11Description = "SYS and SYSTEM-owned objects must not be granted to PUBLIC or non-Oracle-maintained accounts."

var d11Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1068"},
	Mitigations: []string{"M1026"},
}

type D11Grant struct {
	Owner     string
	Object    string
	Grantee   string
	Privilege string
}

type D11Input struct {
	Grants  []D11Grant
	RawRows [][]string
	LoadErr error
}

func checkD11(ctx ScanContext) CheckResult {
	result := evalD11(loadD11Input(ctx))
	result.Code = "D-11"
	result.Description = d11Description
	result.MitreAttack = d11Mitre
	return result
}

func loadD11Input(scanCtx ScanContext) D11Input {
	if scanCtx.MetadataErr != nil {
		return D11Input{LoadErr: scanCtx.MetadataErr}
	}
	const query12c = `SELECT p.owner || '|~|' || p.table_name || '|~|' || p.grantee || '|~|' || p.privilege
FROM dba_tab_privs p
LEFT JOIN dba_users u ON u.username = p.grantee
WHERE p.owner IN ('SYS', 'SYSTEM')
  AND (p.grantee = 'PUBLIC' OR NVL(u.oracle_maintained, 'N') = 'N')
ORDER BY p.owner, p.table_name, p.grantee, p.privilege;`
	// 11g: treat every user/role grantee as reviewable (no oracle_maintained).
	const query11g = `SELECT p.owner || '|~|' || p.table_name || '|~|' || p.grantee || '|~|' || p.privilege
FROM dba_tab_privs p
LEFT JOIN dba_users u ON u.username = p.grantee
LEFT JOIN dba_roles r ON r.role = p.grantee
WHERE p.owner IN ('SYS', 'SYSTEM')
  AND (p.grantee = 'PUBLIC' OR u.username IS NOT NULL OR r.role IS NOT NULL)
ORDER BY p.owner, p.table_name, p.grantee, p.privilege;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D11Input{LoadErr: err}
	}
	grants := make([]D11Grant, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return D11Input{LoadErr: errors.New("D-11 query returned an unexpected row shape")}
		}
		grants = append(grants, D11Grant{
			Owner: sanitizeEvidence(row[0]), Object: sanitizeEvidence(row[1]),
			Grantee: sanitizeEvidence(row[2]), Privilege: sanitizeEvidence(row[3]),
		})
	}
	return D11Input{Grants: grants, RawRows: rows}
}

func evalD11(input D11Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-11", d11Description, d11Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       formatSQLTable([]string{"OWNER", "TABLE_NAME", "GRANTEE", "PRIVILEGE"}, nil),
			ProcessedConfig: formatProcessedRaw(nil),
		}
	}

	evidence := make([]string, 0, len(input.Grants))
	for _, grant := range input.Grants {
		if grant.Owner == "" || grant.Object == "" || grant.Grantee == "" || grant.Privilege == "" {
			return errorResult("D-11", d11Description, d11Mitre, errors.New("grant evidence is incomplete"))
		}
		evidence = append(evidence, fmt.Sprintf("%s.%s:%s:%s",
			sanitizeEvidence(grant.Owner), sanitizeEvidence(grant.Object),
			sanitizeEvidence(grant.Grantee), sanitizeEvidence(grant.Privilege)))
	}
	sort.Strings(evidence)
	return CheckResult{
		Status:           StatusVulnerable,
		RawConfig:        formatSQLTable([]string{"OWNER", "TABLE_NAME", "GRANTEE", "PRIVILEGE"}, input.RawRows),
		VulnerableConfig: strings.Join(evidence, ", "),
		ProcessedConfig:  formatProcessedRaw(input.RawRows),
	}
}
