package main

import (
	"context"
	"errors"
	"fmt"
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
	Version string
	Patches []D25Patch
	LoadErr error
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

	const query = `SELECT TO_CHAR(patch_id) || '|~|' || action || '|~|' || status || '|~|' ||
       TO_CHAR(action_time, 'YYYY-MM-DD"T"HH24:MI:SS') || '|~|' || description
FROM dba_registry_sqlpatch
ORDER BY action_time DESC NULLS LAST, patch_id DESC;`
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D25Input{LoadErr: err}
	}

	patches := make([]D25Patch, 0, len(rows))
	for _, row := range rows {
		if len(row) != 5 {
			return D25Input{LoadErr: errors.New("D-25 query returned an unexpected row shape")}
		}
		patches = append(patches, D25Patch{
			PatchID:     row[0],
			Action:      row[1],
			Status:      row[2],
			ActionTime:  row[3],
			Description: row[4],
		})
	}
	return D25Input{Version: version, Patches: patches}
}

func evalD25(input D25Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-25", d25Description, d25Mitre, input.LoadErr)
	}
	version := sanitizePatchEvidence(input.Version)
	if version == "" {
		return errorResult("D-25", d25Description, d25Mitre, errors.New("required database version is missing"))
	}
	if len(input.Patches) == 0 {
		return errorResult("D-25", d25Description, d25Mitre, errors.New("DBA_REGISTRY_SQLPATCH returned no patch evidence"))
	}

	evidence := make([]string, 0, len(input.Patches)+1)
	evidence = append(evidence, "db_version="+version)
	for i, patch := range input.Patches {
		patchID := sanitizePatchEvidence(patch.PatchID)
		action := strings.ToUpper(sanitizePatchEvidence(patch.Action))
		status := strings.ToUpper(sanitizePatchEvidence(patch.Status))
		actionTime := sanitizePatchEvidence(patch.ActionTime)
		description := sanitizePatchEvidence(patch.Description)
		if err := validateD25Patch(patchID, action, status, actionTime, description); err != nil {
			return errorResult("D-25", d25Description, d25Mitre, fmt.Errorf("patch row %d is malformed: %w", i+1, err))
		}
		evidence = append(evidence, fmt.Sprintf(
			"patch_id=%s; action=%s; status=%s; action_time=%s; description=%s",
			patchID, action, status, actionTime, description,
		))
	}

	result := CheckResult{
		Status:          StatusManual,
		RawConfig:       strings.Join(evidence, " | "),
		ProcessedConfig: "currency=manual_review; compare_collected_patch_evidence_with_current_Oracle_CPU_advisory",
	}
	latestStatus := strings.ToUpper(strings.TrimSpace(input.Patches[0].Status))
	if latestStatus == "FAILED" || latestStatus == "WITH ERRORS" || strings.Contains(latestStatus, "FAIL") {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "latest_patch_action_status=" + sanitizePatchEvidence(latestStatus)
		result.ProcessedConfig = "latest_patch_action=failed; compare_collected_patch_evidence_with_current_Oracle_CPU_advisory"
	}
	return result
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
