package main

import (
	"strconv"
	"strings"
)

type U12Input struct {
	ProfileContent string
}

func checkU12(ctx ScanContext) CheckResult {
	const code = "U-12"
	const description = "Session timeout should be set to 600 seconds (10 minutes) or less."
	mitreAttack := MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1028"},
	}

	input, errs := loadU12Input()

	result := evalU12(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU12Input() (U12Input, []string) {
	paths := []string{
		"/etc/profile",
		"/root/.profile",
		"/etc/csh.login",
		"/etc/csh.cshrc",
	}

	var combined strings.Builder
	for _, path := range paths {
		files, _ := collectFiles(path)
		if len(files) == 0 {
			continue
		}
		combined.WriteString("# FILE: " + files[0].Path + "\n")
		combined.WriteString(files[0].Content)
		combined.WriteString("\n")
	}

	if combined.Len() == 0 {
		return U12Input{}, []string{"session timeout profile files not found (/etc/profile, /etc/csh.login, /etc/csh.cshrc)"}
	}

	return U12Input{ProfileContent: combined.String()}, nil
}

func evalU12(input U12Input) CheckResult {
	content := input.ProfileContent
	tmoutValue := "NOT_FOUND"
	foundTimeout := false
	timeoutOK := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "tmout") {
			// Look for TMOUT=xxx or export TMOUT=xxx
			if idx := strings.Index(lower, "tmout"); idx >= 0 {
				rest := line[idx+5:]
				rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
				rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
				if valStr := extractFirstNumber(rest); valStr != "" {
					tmoutValue = valStr
					foundTimeout = true
					if safeAtoi(valStr) > 0 && safeAtoi(valStr) <= 600 {
						timeoutOK = true
					}
				}
			}
		}
	}

	status := StatusVulnerable
	vulnerableConfig := ""
	if foundTimeout && timeoutOK {
		status = StatusGood
	} else if !foundTimeout {
		vulnerableConfig = buildVulnerableConfig(
			"TMOUT=NOT_FOUND",
			"문제점1. 세션 타임아웃(TMOUT)이 설정되어 있지 않습니다.",
		)
	} else {
		vulnerableConfig = buildVulnerableConfig(
			"TMOUT="+tmoutValue,
			"문제점1. TMOUT 값이 600초를 초과합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("TMOUT="+tmoutValue, "timeout_ok="+strconv.FormatBool(timeoutOK)),
		VulnerableConfig: vulnerableConfig,
	}
}

func extractFirstNumber(s string) string {
	for _, field := range strings.Fields(s) {
		if _, err := strconv.Atoi(field); err == nil {
			return field
		}
		// handle cases like TMOUT=300; or 300 export
		clean := strings.Trim(field, " ;:\"'")
		if _, err := strconv.Atoi(clean); err == nil {
			return clean
		}
	}
	return ""
}
