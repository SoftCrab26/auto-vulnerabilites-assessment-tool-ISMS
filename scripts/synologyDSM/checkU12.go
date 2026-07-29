package main

import (
	"strconv"
	"strings"
)

type U12Input struct {
	Evidence []FileResult
}

func checkU12(ctx ScanContext) CheckResult {
	input, errs := loadU12Input(ctx)
	result := evalU12(input)
	result.Code = "U-12"
	result.Description = "Interactive shell sessions should time out after 600 seconds or less."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1028"},
	}
	return resultWithErrors(result, errs)
}

func loadU12Input(_ ScanContext) (U12Input, []string) {
	files, errs := collectFiles(
		"/etc/profile",
		"/etc.defaults/profile",
		"/root/.profile",
		"/etc/csh.login",
		"/etc/csh.cshrc",
	)
	return U12Input{Evidence: files}, errs
}

func evalU12(input U12Input) CheckResult {
	if len(input.Evidence) == 0 {
		return CheckResult{Status: Error, ErrMsg: "shell timeout evidence is unavailable"}
	}
	raw := dsmU12JoinEvidence(input.Evidence)
	value, found := dsmU12TMOUT(raw)
	readonly := dsmU12ReadonlyTMOUT(raw)
	processed := "TMOUT=" + dsmU12Value(value, found) + " readonly=" + dsmU12Bool(readonly)
	if found && value > 0 && value <= 600 && readonly {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: processed}
	}
	if found && (value <= 0 || value > 600) {
		return CheckResult{
			Status:           Vulnerable,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "TMOUT must be between 1 and 600 seconds",
		}
	}
	if found {
		return CheckResult{
			Status:           Manual,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "TMOUT is suitable but not demonstrably protected from user override",
		}
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  processed,
		VulnerableConfig: "TMOUT is not evident; confirm whether DSM UI and organization policy govern the session",
	}
}

func dsmU12JoinEvidence(files []FileResult) string {
	var parts []string
	for _, file := range files {
		parts = append(parts, "# FILE: "+file.Path+"\n"+file.Content)
	}
	return strings.Join(parts, "\n")
}

func dsmU12TMOUT(raw string) (int, bool) {
	value, found := 0, false
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripUnquotedComment(rawLine))
		if line == "" {
			continue
		}
		for _, field := range strings.Fields(strings.NewReplacer(";", " ", "export ", "").Replace(line)) {
			if !strings.HasPrefix(strings.ToUpper(field), "TMOUT=") {
				continue
			}
			parsed, err := strconv.Atoi(strings.Trim(strings.SplitN(field, "=", 2)[1], `"'`))
			if err == nil {
				value, found = parsed, true
			}
		}
	}
	return value, found
}

func dsmU12ReadonlyTMOUT(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "readonly tmout") ||
		strings.Contains(lower, "typeset -r tmout")
}

func dsmU12Value(value int, found bool) string {
	if !found {
		return "unspecified"
	}
	return strconv.Itoa(value)
}

func dsmU12Bool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
