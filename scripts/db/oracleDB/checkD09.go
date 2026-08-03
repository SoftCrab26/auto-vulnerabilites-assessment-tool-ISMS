package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const d09Description = "FAILED_LOGIN_ATTEMPTS must resolve to a finite positive value for every profile."

var d09Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1110"},
	Mitigations: []string{"M1036"},
}

type D09Profile struct {
	Profile  string
	Declared string
	Resolved string
}

type D09Input struct {
	Profiles []D09Profile
	RawRows  [][]string
	LoadErr  error
}

func checkD09(ctx ScanContext) CheckResult {
	result := evalD09(loadD09Input(ctx))
	result.Code = "D-09"
	result.Description = d09Description
	result.MitreAttack = d09Mitre
	return result
}

func loadD09Input(scanCtx ScanContext) D09Input {
	if scanCtx.MetadataErr != nil {
		return D09Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT p.profile || '|~|' || p.limit || '|~|' ||
       CASE WHEN UPPER(p.limit) = 'DEFAULT' THEN NVL(d.limit, 'DEFAULT') ELSE p.limit END
FROM dba_profiles p
LEFT JOIN dba_profiles d
  ON d.profile = 'DEFAULT'
 AND d.resource_type = 'PASSWORD'
 AND d.resource_name = 'FAILED_LOGIN_ATTEMPTS'
WHERE p.resource_type = 'PASSWORD'
  AND p.resource_name = 'FAILED_LOGIN_ATTEMPTS'
ORDER BY p.profile;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D09Input{LoadErr: err}
	}
	if len(rows) == 0 {
		return D09Input{LoadErr: errors.New("D-09 query returned no profiles")}
	}
	profiles := make([]D09Profile, 0, len(rows))
	for _, row := range rows {
		if len(row) != 3 {
			return D09Input{LoadErr: errors.New("D-09 query returned an unexpected row shape")}
		}
		profiles = append(profiles, D09Profile{
			Profile:  sanitizeEvidence(row[0]),
			Declared: sanitizeEvidence(strings.ToUpper(row[1])),
			Resolved: sanitizeEvidence(strings.ToUpper(row[2])),
		})
	}
	return D09Input{Profiles: profiles, RawRows: rows}
}

func evalD09(input D09Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-09", d09Description, d09Mitre, input.LoadErr)
	}
	if len(input.Profiles) == 0 {
		return errorResult("D-09", d09Description, d09Mitre, errors.New("FAILED_LOGIN_ATTEMPTS evidence is empty"))
	}

	var unlimited, unresolved []string
	for _, profile := range input.Profiles {
		name := sanitizeEvidence(profile.Profile)
		declared := strings.ToUpper(strings.TrimSpace(profile.Declared))
		resolved := strings.ToUpper(strings.TrimSpace(profile.Resolved))
		if name == "" || declared == "" || resolved == "" {
			return errorResult("D-09", d09Description, d09Mitre, errors.New("profile evidence is incomplete"))
		}
		switch resolved {
		case "UNLIMITED":
			unlimited = append(unlimited, name+"=UNLIMITED")
		case "DEFAULT":
			unresolved = append(unresolved, name+"=DEFAULT(unresolved)")
		default:
			value, err := strconv.Atoi(resolved)
			if err != nil || value <= 0 {
				return errorResult("D-09", d09Description, d09Mitre, fmt.Errorf("profile %s returned an unsupported FAILED_LOGIN_ATTEMPTS value", name))
			}
		}
	}
	sort.Strings(unlimited)
	sort.Strings(unresolved)
	rawRows := input.RawRows
	rawConfig := formatSQLTable([]string{"PROFILE", "DECLARED_LIMIT", "RESOLVED_LIMIT"}, rawRows)
	processed := formatProcessedRaw(rawRows)
	result := CheckResult{RawConfig: rawConfig, ProcessedConfig: processed}
	if len(unlimited) > 0 {
		result.Status = StatusVulnerable
		result.VulnerableConfig = strings.Join(unlimited, ", ")
		return result
	}
	if len(unresolved) > 0 {
		result.Status = StatusManual
		return result
	}
	result.Status = StatusGood
	return result
}
