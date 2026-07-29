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
	const query = `SELECT p.owner || '|~|' || p.table_name || '|~|' || p.grantee || '|~|' || p.privilege
FROM dba_tab_privs p
LEFT JOIN dba_users u ON u.username = p.grantee
WHERE p.owner IN ('SYS', 'SYSTEM')
  AND (p.grantee = 'PUBLIC' OR NVL(u.oracle_maintained, 'N') = 'N')
ORDER BY p.owner, p.table_name, p.grantee, p.privilege;`

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
	return D11Input{Grants: grants}
}

func evalD11(input D11Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-11", d11Description, d11Mitre, input.LoadErr)
	}
	if len(input.Grants) == 0 {
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       "risky_sys_system_object_grants=0",
			ProcessedConfig: "public_or_non_oracle_maintained_grants=none",
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
		RawConfig:        strings.Join(evidence, ", "),
		VulnerableConfig: strings.Join(evidence, ", "),
		ProcessedConfig:  fmt.Sprintf("risky_sys_system_object_grants=%d", len(evidence)),
	}
}
