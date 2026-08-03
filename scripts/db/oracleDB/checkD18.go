package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const d18Description = "Privileges and roles granted to PUBLIC must not provide dangerous database capabilities."

var d18Mitre = MitreAttack{
	Tactic:      "Privilege Escalation",
	Techniques:  []string{"T1098"},
	Mitigations: []string{"M1026"},
}

type D18Grant struct {
	Kind      string
	Owner     string
	Object    string
	Privilege string
}

type D18Input struct {
	Grants  []D18Grant
	RawRows [][]string
	LoadErr error
}

func checkD18(ctx ScanContext) CheckResult {
	result := evalD18(loadD18Input(ctx))
	result.Code = "D-18"
	result.Description = d18Description
	result.MitreAttack = d18Mitre
	return result
}

func loadD18Input(scanCtx ScanContext) D18Input {
	if scanCtx.MetadataErr != nil {
		return D18Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT grant_kind || '|~|' || owner_name || '|~|' ||
       object_name || '|~|' || privilege_name
FROM (
    SELECT 'SYSTEM' grant_kind, '-' owner_name, '-' object_name,
           privilege privilege_name
    FROM dba_sys_privs
    WHERE grantee = 'PUBLIC'
    UNION ALL
    SELECT 'OBJECT', owner, table_name, privilege
    FROM dba_tab_privs
    WHERE grantee = 'PUBLIC'
    UNION ALL
    SELECT 'ROLE', '-', '-', granted_role
    FROM dba_role_privs
    WHERE grantee = 'PUBLIC'
)
ORDER BY grant_kind, owner_name, object_name, privilege_name;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D18Input{LoadErr: err}
	}
	grants := make([]D18Grant, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return D18Input{LoadErr: errors.New("D-18 query returned an unexpected row shape")}
		}
		if hasBlankD17Row(row) {
			return D18Input{LoadErr: errors.New("D-18 query returned incomplete grant evidence")}
		}
		grants = append(grants, D18Grant{
			Kind: row[0], Owner: row[1], Object: row[2], Privilege: row[3],
		})
	}
	return D18Input{Grants: grants, RawRows: rows}
}

func evalD18(input D18Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-18", d18Description, d18Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       formatSQLTable([]string{"GRANT_KIND", "OWNER_NAME", "OBJECT_NAME", "PRIVILEGE_NAME"}, nil),
			ProcessedConfig: formatProcessedRaw(nil),
		}
	}

	var dangerous, review []string
	for _, grant := range input.Grants {
		evidence := fmt.Sprintf("kind=%s; owner=%s; object=%s; privilege=%s",
			sanitizeEvidence(grant.Kind), sanitizeEvidence(grant.Owner),
			sanitizeEvidence(grant.Object), sanitizeEvidence(grant.Privilege))
		if isDangerousD18Grant(grant) {
			dangerous = append(dangerous, evidence)
		} else {
			review = append(review, evidence)
		}
	}
	sort.Strings(dangerous)
	sort.Strings(review)

	result := CheckResult{
		RawConfig:       formatSQLTable([]string{"GRANT_KIND", "OWNER_NAME", "OBJECT_NAME", "PRIVILEGE_NAME"}, input.RawRows),
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
	if len(dangerous) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(dangerous, " | ")
		return result
	}
	result.Status = StatusManual
	return result
}

func isDangerousD18Grant(grant D18Grant) bool {
	kind := strings.ToUpper(strings.TrimSpace(grant.Kind))
	privilege := strings.ToUpper(strings.TrimSpace(grant.Privilege))
	if kind == "ROLE" {
		return privilege == "DBA"
	}
	if kind == "SYSTEM" {
		if strings.Contains(privilege, " ANY ") || strings.HasSuffix(privilege, " ANY") {
			return true
		}
		switch privilege {
		case "ALTER USER", "BECOME USER", "CREATE USER", "DROP USER",
			"EXEMPT ACCESS POLICY", "GRANT ANY PRIVILEGE", "GRANT ANY ROLE":
			return true
		}
	}
	if kind != "OBJECT" || privilege != "EXECUTE" ||
		!strings.EqualFold(strings.TrimSpace(grant.Owner), "SYS") {
		return false
	}
	powerfulPackages := map[string]bool{
		"DBMS_JOB": true, "DBMS_SCHEDULER": true, "DBMS_SQL": true,
		"DBMS_SYS_SQL": true, "UTL_FILE": true, "UTL_HTTP": true,
		"UTL_SMTP": true, "UTL_TCP": true,
	}
	return powerfulPackages[strings.ToUpper(strings.TrimSpace(grant.Object))]
}
