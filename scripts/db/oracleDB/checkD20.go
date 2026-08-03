package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const d20Description = "Database object owners must be reviewed against the organization's authorized owner list."

var d20Mitre = MitreAttack{
	Tactic:      "Persistence",
	Techniques:  []string{"T1136"},
	Mitigations: []string{"M1018"},
}

type D20Owner struct {
	Owner            string
	ObjectCount      int
	OracleMaintained string
	AccountStatus    string
}

type D20Input struct {
	Owners  []D20Owner
	RawRows [][]string
	LoadErr error
}

func checkD20(ctx ScanContext) CheckResult {
	result := evalD20(loadD20Input(ctx))
	result.Code = "D-20"
	result.Description = d20Description
	result.MitreAttack = d20Mitre
	return result
}

func loadD20Input(scanCtx ScanContext) D20Input {
	if scanCtx.MetadataErr != nil {
		return D20Input{LoadErr: scanCtx.MetadataErr}
	}
	const query12c = `SELECT o.owner || '|~|' || COUNT(*) || '|~|' ||
       NVL(u.oracle_maintained, 'N') || '|~|' || NVL(u.account_status, 'UNKNOWN')
FROM dba_objects o
LEFT JOIN dba_users u ON u.username = o.owner
GROUP BY o.owner, NVL(u.oracle_maintained, 'N'), NVL(u.account_status, 'UNKNOWN')
ORDER BY o.owner;`
	const query11g = `SELECT o.owner || '|~|' || COUNT(*) || '|~|' ||
       'N' || '|~|' || NVL(u.account_status, 'UNKNOWN')
FROM dba_objects o
LEFT JOIN dba_users u ON u.username = o.owner
GROUP BY o.owner, NVL(u.account_status, 'UNKNOWN')
ORDER BY o.owner;`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D20Input{LoadErr: err}
	}
	owners := make([]D20Owner, 0, len(rows))
	for _, row := range rows {
		if len(row) != 4 {
			return D20Input{LoadErr: errors.New("D-20 query returned an unexpected row shape")}
		}
		if hasBlankD17Row(row) {
			return D20Input{LoadErr: errors.New("D-20 query returned incomplete owner evidence")}
		}
		count, err := strconv.Atoi(strings.TrimSpace(row[1]))
		if err != nil || count < 1 {
			return D20Input{LoadErr: errors.New("D-20 query returned an invalid object count")}
		}
		owners = append(owners, D20Owner{
			Owner: row[0], ObjectCount: count, OracleMaintained: row[2], AccountStatus: row[3],
		})
	}
	return D20Input{Owners: owners, RawRows: rows}
}

func evalD20(input D20Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-20", d20Description, d20Mitre, input.LoadErr)
	}

	sampleSchemas := map[string]bool{
		"BI": true, "HR": true, "IX": true, "OE": true, "PM": true,
		"SCOTT": true, "SH": true,
	}
	var evidence, vulnerable []string
	for _, owner := range input.Owners {
		item := fmt.Sprintf("owner=%s; objects=%d; oracle_maintained=%s; account_status=%s",
			sanitizeEvidence(owner.Owner), owner.ObjectCount,
			sanitizeEvidence(owner.OracleMaintained), sanitizeEvidence(owner.AccountStatus))
		evidence = append(evidence, item)
		if sampleSchemas[strings.ToUpper(strings.TrimSpace(owner.Owner))] &&
			strings.EqualFold(strings.TrimSpace(owner.AccountStatus), "OPEN") {
			vulnerable = append(vulnerable, item)
		}
	}
	sort.Strings(evidence)
	sort.Strings(vulnerable)
	result := CheckResult{
		Status:          StatusManual,
		RawConfig:       formatSQLTable([]string{"OWNER", "OBJECT_COUNT", "ORACLE_MAINTAINED", "ACCOUNT_STATUS"}, input.RawRows),
		ProcessedConfig: formatProcessedRaw(input.RawRows),
	}
	if len(vulnerable) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(vulnerable, " | ")
	}
	return result
}
