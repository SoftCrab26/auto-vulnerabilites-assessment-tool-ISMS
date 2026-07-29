package main

import (
	"context"
	"errors"
	"strings"
)

const d03Description = "Password lifetime and complexity settings must meet institutional policy."

var d03Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1110"},
	Mitigations: []string{"M1027"},
}

type D03Setting struct {
	Profile  string
	Resource string
	Limit    string
}

type D03Input struct {
	Settings []D03Setting
	LoadErr  error
}

func checkD03(ctx ScanContext) CheckResult {
	result := evalD03(loadD03Input(ctx))
	result.Code = "D-03"
	result.Description = d03Description
	result.MitreAttack = d03Mitre
	return result
}

func loadD03Input(scanCtx ScanContext) D03Input {
	if scanCtx.MetadataErr != nil {
		return D03Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT profile || '|~|' || resource_name || '|~|' || limit
FROM dba_profiles
WHERE resource_type = 'PASSWORD'
  AND resource_name IN ('PASSWORD_LIFE_TIME', 'PASSWORD_VERIFY_FUNCTION', 'FAILED_LOGIN_ATTEMPTS')
ORDER BY profile, resource_name;`
	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D03Input{LoadErr: err}
	}
	settings := make([]D03Setting, 0, len(rows))
	for _, row := range rows {
		if len(row) != 3 || strings.TrimSpace(row[0]) == "" || strings.TrimSpace(row[1]) == "" || strings.TrimSpace(row[2]) == "" {
			return D03Input{LoadErr: errors.New("D-03 query returned an unexpected row shape")}
		}
		settings = append(settings, D03Setting{
			Profile: sanitizeEvidence(row[0]), Resource: sanitizeEvidence(row[1]), Limit: sanitizeEvidence(row[2]),
		})
	}
	return D03Input{Settings: settings}
}

func evalD03(input D03Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-03", d03Description, d03Mitre, input.LoadErr)
	}
	if len(input.Settings) == 0 {
		return errorResult("D-03", d03Description, d03Mitre, errors.New("D-03 password policy evidence is missing"))
	}

	var evidence, vulnerable []string
	for _, setting := range input.Settings {
		profile := sanitizeEvidence(setting.Profile)
		resource := strings.ToUpper(strings.TrimSpace(setting.Resource))
		limit := strings.ToUpper(strings.TrimSpace(setting.Limit))
		if profile == "" || resource == "" || limit == "" {
			return errorResult("D-03", d03Description, d03Mitre, errors.New("D-03 password policy contains an empty required value"))
		}
		item := "profile=" + profile + ", resource=" + sanitizeEvidence(resource) + ", limit=" + sanitizeEvidence(limit)
		evidence = append(evidence, item)
		if resource == "PASSWORD_LIFE_TIME" && limit == "UNLIMITED" {
			vulnerable = append(vulnerable, item)
		}
		if resource == "PASSWORD_VERIFY_FUNCTION" && (limit == "NULL" || limit == "NONE" || limit == "UNLIMITED") {
			vulnerable = append(vulnerable, item)
		}
	}
	raw := strings.Join(evidence, "; ")
	if len(vulnerable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        raw,
			VulnerableConfig: strings.Join(vulnerable, "; "),
			ProcessedConfig:  "password_expiration_or_complexity_control_clearly_disabled=true",
		}
	}
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       raw,
		ProcessedConfig: "Human decision required: compare every profile's lifetime, complexity function, and failed-login threshold with the institution's approved password policy.",
	}
}
