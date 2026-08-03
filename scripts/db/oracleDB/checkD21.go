package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const d21Description = "Delegable object and system privileges must be limited to explicitly approved principals."

var d21Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1098"},
	Mitigations: []string{"M1026"},
}

type D21Grant struct {
	Kind      string
	Grantee   string
	Owner     string
	Object    string
	Privilege string
}

type D21Input struct {
	Grants  []D21Grant
	RawRows [][]string
	LoadErr error
}

func checkD21(ctx ScanContext) CheckResult {
	result := evalD21(loadD21Input(ctx))
	result.Code = "D-21"
	result.Description = d21Description
	result.MitreAttack = d21Mitre
	return result
}

func loadD21Input(scanCtx ScanContext) D21Input {
	if scanCtx.MetadataErr != nil {
		return D21Input{LoadErr: scanCtx.MetadataErr}
	}
	const query12c = `SELECT grant_kind || '|~|' || grantee || '|~|' ||
       owner_name || '|~|' || object_name || '|~|' || privilege_name
FROM (
    SELECT 'OBJECT' grant_kind, p.grantee, p.owner owner_name,
           p.table_name object_name, p.privilege privilege_name
    FROM dba_tab_privs p
    LEFT JOIN dba_users u ON u.username = p.grantee
    LEFT JOIN dba_roles r ON r.role = p.grantee
    WHERE p.grantable = 'YES'
      AND (p.grantee = 'PUBLIC'
           OR NVL(u.oracle_maintained, NVL(r.oracle_maintained, 'N')) = 'N')
    UNION ALL
    SELECT 'SYSTEM', p.grantee, '-', '-', p.privilege
    FROM dba_sys_privs p
    LEFT JOIN dba_users u ON u.username = p.grantee
    LEFT JOIN dba_roles r ON r.role = p.grantee
    WHERE p.admin_option = 'YES'
      AND (p.grantee = 'PUBLIC'
           OR NVL(u.oracle_maintained, NVL(r.oracle_maintained, 'N')) = 'N')
)
ORDER BY grant_kind, grantee, owner_name, object_name, privilege_name;`
	const query11g = `SELECT grant_kind || '|~|' || grantee || '|~|' ||
       owner_name || '|~|' || object_name || '|~|' || privilege_name
FROM (
    SELECT 'OBJECT' grant_kind, p.grantee, p.owner owner_name,
           p.table_name object_name, p.privilege privilege_name
    FROM dba_tab_privs p
    LEFT JOIN dba_users u ON u.username = p.grantee
    LEFT JOIN dba_roles r ON r.role = p.grantee
    WHERE p.grantable = 'YES'
      AND (p.grantee = 'PUBLIC' OR u.username IS NOT NULL OR r.role IS NOT NULL)
    UNION ALL
    SELECT 'SYSTEM', p.grantee, '-', '-', p.privilege
    FROM dba_sys_privs p
    LEFT JOIN dba_users u ON u.username = p.grantee
    LEFT JOIN dba_roles r ON r.role = p.grantee
    WHERE p.admin_option = 'YES'
      AND (p.grantee = 'PUBLIC' OR u.username IS NOT NULL OR r.role IS NOT NULL)
)
ORDER BY grant_kind, grantee, owner_name, object_name, privilege_name;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D21Input{LoadErr: err}
	}
	grants := make([]D21Grant, 0, len(rows))
	for _, row := range rows {
		if len(row) != 5 {
			return D21Input{LoadErr: errors.New("D-21 query returned an unexpected row shape")}
		}
		if hasBlankD17Row(row) {
			return D21Input{LoadErr: errors.New("D-21 query returned incomplete delegation evidence")}
		}
		grants = append(grants, D21Grant{
			Kind: row[0], Grantee: row[1], Owner: row[2], Object: row[3], Privilege: row[4],
		})
	}
	return D21Input{Grants: grants, RawRows: rows}
}

func evalD21(input D21Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-21", d21Description, d21Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       formatSQLTable([]string{"GRANT_KIND", "GRANTEE", "OWNER_NAME", "OBJECT_NAME", "PRIVILEGE_NAME"}, nil),
			ProcessedConfig: formatProcessedRaw(nil),
		}
	}

	var broad, review []string
	for _, grant := range input.Grants {
		item := fmt.Sprintf("kind=%s; grantee=%s; owner=%s; object=%s; privilege=%s",
			sanitizeEvidence(grant.Kind), sanitizeEvidence(grant.Grantee),
			sanitizeEvidence(grant.Owner), sanitizeEvidence(grant.Object),
			sanitizeEvidence(grant.Privilege))
		if isBroadD21Grant(grant) {
			broad = append(broad, item)
		} else {
			review = append(review, item)
		}
	}
	sort.Strings(broad)
	sort.Strings(review)

	result := CheckResult{
		RawConfig:       formatSQLTable([]string{"GRANT_KIND", "GRANTEE", "OWNER_NAME", "OBJECT_NAME", "PRIVILEGE_NAME"}, input.RawRows),
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
	if len(broad) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(broad, " | ")
		return result
	}
	result.Status = StatusManual
	return result
}

func isBroadD21Grant(grant D21Grant) bool {
	if strings.EqualFold(strings.TrimSpace(grant.Grantee), "PUBLIC") {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(grant.Kind), "SYSTEM") {
		return false
	}
	privilege := strings.ToUpper(strings.TrimSpace(grant.Privilege))
	if strings.Contains(privilege, " ANY ") ||
		strings.HasSuffix(privilege, " ANY") ||
		strings.HasPrefix(privilege, "GRANT ANY ") {
		return true
	}
	switch privilege {
	case "ALTER USER", "BECOME USER", "CREATE USER", "DROP USER",
		"EXEMPT ACCESS POLICY":
		return true
	default:
		return false
	}
}
