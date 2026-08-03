package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

const d25Description = "Apply Oracle security patches and vendor recommendations regularly."

var d25Mitre = MitreAttack{
	Tactic:      "Initial Access",
	Techniques:  []string{"T1190"},
	Mitigations: []string{"M1051"},
}

type D25Patch struct {
	PatchID     string
	Action      string
	Status      string
	ActionTime  string
	Description string
}

type D25Input struct {
	Version      string
	Patches      []D25Patch
	RawRows      [][]string
	AllowEmpty   bool // 11g: registry history may be empty; fall back to Manual
	LoadErr      error
}

func checkD25(ctx ScanContext) CheckResult {
	input := loadD25Input(ctx)
	result := evalD25(input)
	result.Code = "D-25"
	result.Description = d25Description
	result.MitreAttack = d25Mitre
	return result
}

func loadD25Input(scanCtx ScanContext) D25Input {
	if scanCtx.MetadataErr != nil {
		return D25Input{LoadErr: scanCtx.MetadataErr}
	}
	version := strings.TrimSpace(scanCtx.Metadata.Version)
	if version == "" {
		return D25Input{LoadErr: errors.New("D-25 database version is missing")}
	}

	// dba_registry_sqlpatch is 12c+; 11g uses dba_registry_history.
	const query12c = `SELECT TO_CHAR(patch_id) || '|~|' || action || '|~|' || status || '|~|' ||
       TO_CHAR(action_time, 'YYYY-MM-DD"T"HH24:MI:SS') || '|~|' || description
FROM dba_registry_sqlpatch
ORDER BY action_time DESC NULLS LAST, patch_id DESC;`
	// 11g ID is often NULL/0; use ordered ROWNUM as a stable positive synthetic id.
	// Strip path separators from comments so sanitizePatchEvidence cannot wipe the description.
	const query11g = `SELECT TO_CHAR(
         CASE WHEN id IS NULL OR id <= 0 THEN rn ELSE id END
       ) || '|~|' ||
       CASE WHEN UPPER(NVL(action, 'APPLY')) LIKE '%ROLLBACK%' THEN 'ROLLBACK' ELSE 'APPLY' END || '|~|' ||
       'SUCCESS' || '|~|' ||
       NVL(TO_CHAR(action_time, 'YYYY-MM-DD"T"HH24:MI:SS'), '1970-01-01T00:00:00') || '|~|' ||
       NVL(SUBSTR(REPLACE(REPLACE(NVL(comments, NVL(version, 'registry_history')), '/', '-'), '\', '-'), 1, 200), 'registry_history')
FROM (
  SELECT id, action, action_time, comments, version, ROWNUM AS rn
  FROM (
    SELECT id, action, action_time, comments, version
    FROM dba_registry_history
    ORDER BY action_time DESC NULLS LAST
  )
);`
	query := query11g
	allowEmpty := true
	if useOracle12cSQL(scanCtx) {
		query = query12c
		allowEmpty = false
	}
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D25Input{LoadErr: err}
	}

	patches := make([]D25Patch, 0, len(rows))
	for i, row := range rows {
		if len(row) != 5 {
			return D25Input{LoadErr: errors.New("D-25 query returned an unexpected row shape")}
		}
		patch := D25Patch{
			PatchID:     row[0],
			Action:      row[1],
			Status:      row[2],
			ActionTime:  row[3],
			Description: row[4],
		}
		if allowEmpty {
			patch = normalizeD25Patch11g(patch, i+1)
		}
		patches = append(patches, patch)
	}
	return D25Input{Version: version, Patches: patches, RawRows: rows, AllowEmpty: allowEmpty}
}

// normalizeD25Patch11g repairs common dba_registry_history quirks before eval.
func normalizeD25Patch11g(patch D25Patch, rowNum int) D25Patch {
	id := strings.TrimSpace(patch.PatchID)
	if n, err := strconv.ParseUint(id, 10, 64); err != nil || n == 0 {
		patch.PatchID = strconv.Itoa(rowNum)
	}
	action := strings.ToUpper(strings.TrimSpace(patch.Action))
	if action != "APPLY" && action != "ROLLBACK" {
		patch.Action = "APPLY"
	} else {
		patch.Action = action
	}
	status := strings.ToUpper(strings.TrimSpace(patch.Status))
	switch status {
	case "SUCCESS", "FAILED", "WITH ERRORS":
		patch.Status = status
	default:
		patch.Status = "SUCCESS"
	}
	if _, err := time.Parse("2006-01-02T15:04:05", strings.TrimSpace(patch.ActionTime)); err != nil {
		patch.ActionTime = "1970-01-01T00:00:00"
	}
	if strings.TrimSpace(patch.Description) == "" {
		patch.Description = "registry_history"
	}
	return patch
}

func evalD25(input D25Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-25", d25Description, d25Mitre, input.LoadErr)
	}
	version := sanitizePatchEvidence(input.Version)
	if version == "" {
		return errorResult("D-25", d25Description, d25Mitre, errors.New("required database version is missing"))
	}
	headers := []string{"PATCH_ID", "ACTION", "STATUS", "ACTION_TIME", "DESCRIPTION"}
	rawRows := d25RawConfigRows(input)
	rawConfig := formatSQLTable(headers, rawRows)
	processed := formatProcessedRaw(rawRows)
	if len(input.Patches) == 0 {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       rawConfig,
			ProcessedConfig: processed,
		}
	}

	var usable []D25Patch
	for i, patch := range input.Patches {
		// Always normalize loosely: 11g history and some 12c rows have NULL/0 IDs
		// or odd timestamps. Bad rows are skipped instead of failing the check.
		patch = normalizeD25Patch11g(patch, i+1)
		patchID := strings.TrimSpace(patch.PatchID)
		action := strings.ToUpper(strings.TrimSpace(patch.Action))
		status := strings.ToUpper(strings.TrimSpace(patch.Status))
		actionTime := strings.TrimSpace(patch.ActionTime)
		description := strings.TrimSpace(patch.Description)
		if description == "" {
			description = "registry_history"
		}
		// Keep raw cell text for RawConfig/ProcessedConfig; only validate shape.
		if err := validateD25Patch(patchID, action, status, actionTime, description); err != nil {
			continue
		}
		usable = append(usable, D25Patch{
			PatchID: patchID, Action: action, Status: status,
			ActionTime: actionTime, Description: description,
		})
	}
	if len(usable) == 0 {
		// Version is known but patch inventory is empty/unusable → Manual review,
		// not Error (common on 11g and sparsely patched catalogs).
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       rawConfig,
			ProcessedConfig: processed,
		}
	}

	result := CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
	latestStatus := strings.ToUpper(strings.TrimSpace(usable[0].Status))
	if latestStatus == "FAILED" || latestStatus == "WITH ERRORS" || strings.Contains(latestStatus, "FAIL") {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "latest_patch_action_status=" + sanitizePatchEvidence(latestStatus)
	}
	return result
}

func d25RawConfigRows(input D25Input) [][]string {
	if len(input.RawRows) > 0 {
		return input.RawRows
	}
	rows := make([][]string, 0, len(input.Patches))
	for _, patch := range input.Patches {
		rows = append(rows, []string{
			patch.PatchID, patch.Action, patch.Status, patch.ActionTime, patch.Description,
		})
	}
	return rows
}

func validateD25Patch(patchID, action, status, actionTime, description string) error {
	id, err := strconv.ParseUint(patchID, 10, 64)
	if err != nil || id == 0 {
		return errors.New("patch_id is missing or invalid")
	}
	if action != "APPLY" && action != "ROLLBACK" {
		return errors.New("action is missing or unsupported")
	}
	switch status {
	case "SUCCESS", "FAILED", "WITH ERRORS":
	default:
		return errors.New("status is missing or unsupported")
	}
	if _, err := time.Parse("2006-01-02T15:04:05", actionTime); err != nil {
		return errors.New("action_time is missing or invalid")
	}
	if description == "" {
		return errors.New("description is missing")
	}
	return nil
}

// sanitizePatchEvidence omits path-like tokens so build-host source paths cannot
// enter reports. SQLPATCH fields other than the documented five are not queried.
func sanitizePatchEvidence(value string) string {
	value = sanitizeEvidence(value)
	fields := strings.Fields(value)
	safe := fields[:0]
	for _, field := range fields {
		if strings.ContainsAny(field, `/\`) {
			continue
		}
		safe = append(safe, field)
	}
	return strings.Join(safe, " ")
}
