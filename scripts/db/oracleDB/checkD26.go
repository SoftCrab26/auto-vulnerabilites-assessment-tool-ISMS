package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const d26Description = "Configure database auditing to meet the organization's audit scope and retention policy."

var d26Mitre = MitreAttack{
	Tactic:      "Defense Evasion",
	Techniques:  []string{"T1562.002"},
	Mitigations: []string{"M1047"},
}

type D26Input struct {
	AuditTrail                 string
	UnifiedAuditSGAQueueSize   string
	UnifiedAuditingOption      string
	UnifiedEnabledPolicyCount  string
	LegacyStatementOptionCount string
	LegacyPrivilegeOptionCount string
	LegacyObjectOptionCount    string
	RawRows                    [][]string
	LoadErr                    error
}

func checkD26(ctx ScanContext) CheckResult {
	input := loadD26Input(ctx)
	result := evalD26(input)
	result.Code = "D-26"
	result.Description = d26Description
	result.MitreAttack = d26Mitre
	return result
}

func loadD26Input(scanCtx ScanContext) D26Input {
	if scanCtx.MetadataErr != nil {
		return D26Input{LoadErr: scanCtx.MetadataErr}
	}

	// This query deliberately returns configuration values and aggregate counts
	// only. It never reads audit events, user SQL text, or account credentials.
	// Unified Auditing views/parameters are 12c+; 11g uses legacy audit_* only.
	const query12c = `SELECT p.value || '|~|' ||
       (SELECT value FROM v$parameter WHERE name = 'unified_audit_sga_queue_size') || '|~|' ||
       (SELECT value FROM v$option WHERE parameter = 'Unified Auditing') || '|~|' ||
       (SELECT TO_CHAR(COUNT(DISTINCT policy_name)) FROM audit_unified_enabled_policies) || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_stmt_audit_opts) || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_priv_audit_opts) || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_obj_audit_opts)
FROM v$parameter p
WHERE p.name = 'audit_trail';`
	const query11g = `SELECT p.value || '|~|' ||
       '0' || '|~|' ||
       'FALSE' || '|~|' ||
       '0' || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_stmt_audit_opts) || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_priv_audit_opts) || '|~|' ||
       (SELECT TO_CHAR(COUNT(*)) FROM dba_obj_audit_opts)
FROM v$parameter p
WHERE p.name = 'audit_trail';`
	query := query11g
	if useOracle12cSQL(scanCtx) {
		query = query12c
	}
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D26Input{LoadErr: err}
	}
	if len(rows) != 1 || len(rows[0]) != 7 {
		return D26Input{LoadErr: errors.New("D-26 query did not return exactly one complete audit configuration row")}
	}
	row := rows[0]
	return D26Input{
		AuditTrail:                 row[0],
		UnifiedAuditSGAQueueSize:   row[1],
		UnifiedAuditingOption:      row[2],
		UnifiedEnabledPolicyCount:  row[3],
		LegacyStatementOptionCount: row[4],
		LegacyPrivilegeOptionCount: row[5],
		LegacyObjectOptionCount:    row[6],
		RawRows:                    rows,
	}
}

func evalD26(input D26Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-26", d26Description, d26Mitre, input.LoadErr)
	}

	auditTrail := strings.ToUpper(sanitizeEvidence(input.AuditTrail))
	unifiedOption := strings.ToUpper(sanitizeEvidence(input.UnifiedAuditingOption))
	if !validAuditTrail(auditTrail) {
		return errorResult("D-26", d26Description, d26Mitre, errors.New("audit_trail is missing or unsupported"))
	}
	if unifiedOption != "TRUE" && unifiedOption != "FALSE" {
		return errorResult("D-26", d26Description, d26Mitre, errors.New("Unified Auditing option is missing or invalid"))
	}

	if _, err := parseD26Count("unified_audit_sga_queue_size", input.UnifiedAuditSGAQueueSize); err != nil {
		return errorResult("D-26", d26Description, d26Mitre, err)
	}
	unifiedPolicies, err := parseD26Count("enabled unified audit policy count", input.UnifiedEnabledPolicyCount)
	if err != nil {
		return errorResult("D-26", d26Description, d26Mitre, err)
	}
	statementOptions, err := parseD26Count("legacy statement audit option count", input.LegacyStatementOptionCount)
	if err != nil {
		return errorResult("D-26", d26Description, d26Mitre, err)
	}
	privilegeOptions, err := parseD26Count("legacy privilege audit option count", input.LegacyPrivilegeOptionCount)
	if err != nil {
		return errorResult("D-26", d26Description, d26Mitre, err)
	}
	objectOptions, err := parseD26Count("legacy object audit option count", input.LegacyObjectOptionCount)
	if err != nil {
		return errorResult("D-26", d26Description, d26Mitre, err)
	}

	rawRows := d26RawConfigRows(input)
	rawConfig := formatSQLTable([]string{
		"AUDIT_TRAIL", "UNIFIED_AUDIT_SGA_QUEUE_SIZE", "UNIFIED_AUDITING_OPTION",
		"ENABLED_UNIFIED_POLICY_COUNT", "LEGACY_STATEMENT_OPTION_COUNT",
		"LEGACY_PRIVILEGE_OPTION_COUNT", "LEGACY_OBJECT_OPTION_COUNT",
	}, rawRows)
	processed := formatProcessedRaw(rawRows)
	legacyOptionCount := statementOptions + privilegeOptions + objectOptions
	enabled := auditTrail != "NONE" || unifiedOption == "TRUE" || unifiedPolicies > 0 || legacyOptionCount > 0
	if !enabled {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        rawConfig,
			VulnerableConfig: "auditing_disabled=true; enabled_policy_count=0; legacy_audit_option_count=0",
			ProcessedConfig:  processed,
		}
	}
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
}

func validAuditTrail(value string) bool {
	switch value {
	case "NONE", "OS", "DB", "DB, EXTENDED", "XML", "XML, EXTENDED":
		return true
	default:
		return false
	}
}

func parseD26Count(name, value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("%s is missing", name)
	}
	count, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid", name)
	}
	return count, nil
}

func d26RawConfigRows(input D26Input) [][]string {
	if len(input.RawRows) > 0 {
		return input.RawRows
	}
	return [][]string{{
		input.AuditTrail,
		input.UnifiedAuditSGAQueueSize,
		input.UnifiedAuditingOption,
		input.UnifiedEnabledPolicyCount,
		input.LegacyStatementOptionCount,
		input.LegacyPrivilegeOptionCount,
		input.LegacyObjectOptionCount,
	}}
}
