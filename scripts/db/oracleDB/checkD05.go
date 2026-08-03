package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

const d05Description = "Password profiles must restrict reuse by count or time."

var d05Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1110"},
	Mitigations: []string{"M1027"},
}

type D05Profile struct {
	Name      string
	ReuseMax  string
	ReuseTime string
}

type D05Input struct {
	Profiles []D05Profile
	RawRows  [][]string
	LoadErr  error
}

func checkD05(ctx ScanContext) CheckResult {
	result := evalD05(loadD05Input(ctx))
	result.Code = "D-05"
	result.Description = d05Description
	result.MitreAttack = d05Mitre
	return result
}

func loadD05Input(scanCtx ScanContext) D05Input {
	if scanCtx.MetadataErr != nil {
		return D05Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT profile || '|~|' ||
       MAX(CASE WHEN resource_name = 'PASSWORD_REUSE_MAX' THEN limit END) || '|~|' ||
       MAX(CASE WHEN resource_name = 'PASSWORD_REUSE_TIME' THEN limit END)
FROM dba_profiles
WHERE resource_type = 'PASSWORD'
  AND resource_name IN ('PASSWORD_REUSE_MAX', 'PASSWORD_REUSE_TIME')
GROUP BY profile
ORDER BY profile;`
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D05Input{LoadErr: err}
	}
	profiles := make([]D05Profile, 0, len(rows))
	for _, row := range rows {
		if len(row) != 3 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" || strings.TrimSpace(row[2]) == "" {
			return D05Input{LoadErr: errors.New("D-05 query returned an unexpected row shape")}
		}
		profiles = append(profiles, D05Profile{
			Name: sanitizeEvidence(row[0]), ReuseMax: sanitizeEvidence(row[1]), ReuseTime: sanitizeEvidence(row[2]),
		})
	}
	return D05Input{Profiles: profiles, RawRows: rows}
}

func evalD05(input D05Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-05", d05Description, d05Mitre, input.LoadErr)
	}
	if len(input.Profiles) == 0 {
		return errorResult("D-05", d05Description, d05Mitre, errors.New("D-05 password reuse evidence is missing"))
	}

	var defaultProfile *D05Profile
	for i := range input.Profiles {
		if strings.EqualFold(strings.TrimSpace(input.Profiles[i].Name), "DEFAULT") {
			if defaultProfile != nil {
				return errorResult("D-05", d05Description, d05Mitre, errors.New("D-05 returned duplicate DEFAULT profiles"))
			}
			defaultProfile = &input.Profiles[i]
		}
	}

	var vulnerable []string
	unresolved := false
	for _, profile := range input.Profiles {
		name := sanitizeEvidence(profile.Name)
		reuseMax := strings.ToUpper(strings.TrimSpace(profile.ReuseMax))
		reuseTime := strings.ToUpper(strings.TrimSpace(profile.ReuseTime))
		if name == "" || reuseMax == "" || reuseTime == "" {
			return errorResult("D-05", d05Description, d05Mitre, errors.New("D-05 password reuse evidence contains an empty required value"))
		}

		resolvedMax, okMax := resolveD05Limit(reuseMax, defaultProfile, true)
		resolvedTime, okTime := resolveD05Limit(reuseTime, defaultProfile, false)
		if !okMax || !okTime {
			unresolved = true
			continue
		}
		if (resolvedMax != "UNLIMITED" && !d05FiniteLimit(resolvedMax)) ||
			(resolvedTime != "UNLIMITED" && !d05FiniteLimit(resolvedTime)) {
			return errorResult("D-05", d05Description, d05Mitre, errors.New("D-05 returned an unsupported password reuse limit"))
		}
		if resolvedMax == "UNLIMITED" && resolvedTime == "UNLIMITED" {
			vulnerable = append(vulnerable, "profile="+name+", effective_password_reuse_max=UNLIMITED, effective_password_reuse_time=UNLIMITED")
		}
	}
	rawConfig := formatSQLTable([]string{"PROFILE", "PASSWORD_REUSE_MAX", "PASSWORD_REUSE_TIME"}, input.RawRows)
	processed := formatProcessedRaw(input.RawRows)
	if unresolved {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       rawConfig,
			ProcessedConfig: processed,
		}
	}
	if len(vulnerable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        rawConfig,
			VulnerableConfig: strings.Join(vulnerable, "; "),
			ProcessedConfig:  processed,
		}
	}
	return CheckResult{
		Status:          StatusGood,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
}

func resolveD05Limit(value string, defaultProfile *D05Profile, useMax bool) (string, bool) {
	if value != "DEFAULT" {
		return value, true
	}
	if defaultProfile == nil {
		return "", false
	}
	resolved := defaultProfile.ReuseTime
	if useMax {
		resolved = defaultProfile.ReuseMax
	}
	resolved = strings.ToUpper(strings.TrimSpace(resolved))
	if resolved == "" || resolved == "DEFAULT" {
		return "", false
	}
	return resolved, true
}

func d05FiniteLimit(value string) bool {
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && number >= 0
}
