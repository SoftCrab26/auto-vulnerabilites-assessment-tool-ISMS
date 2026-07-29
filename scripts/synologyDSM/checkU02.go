package main

import (
	"strconv"
	"strings"
)

type U02Input struct {
	Evidence []FileResult
}

func checkU02(ctx ScanContext) CheckResult {
	input, errs := loadU02Input(ctx)
	result := evalU02(input)
	result.Code = "U-02"
	result.Description = "Password complexity must be enforced by DSM or PAM."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1110"},
		Mitigations: []string{"M1027"},
	}
	return resultWithErrors(result, errs)
}

func loadU02Input(_ ScanContext) (U02Input, []string) {
	paths := []string{
		"/etc/pam.d/common-password",
		"/etc/pam.d/system-auth",
		"/etc/security/pwquality.conf",
		"/etc/login.defs",
		"/etc/synoinfo.conf",
		"/etc.defaults/synoinfo.conf",
	}
	files, errs := collectFiles(paths...)
	return U02Input{Evidence: files}, errs
}

func evalU02(input U02Input) CheckResult {
	if len(input.Evidence) == 0 {
		return CheckResult{Status: Error, ErrMsg: "password policy evidence is unavailable"}
	}
	raw := dsmU02JoinEvidence(input.Evidence)
	lower := strings.ToLower(raw)
	module := "not_found"
	if strings.Contains(lower, "pam_pwquality.so") {
		module = "pam_pwquality"
	} else if strings.Contains(lower, "pam_cracklib.so") {
		module = "pam_cracklib"
	}
	minLen, hasMinLen := dsmU02LastIntegerOption(raw, "minlen", "pass_min_len", "password_min_length")
	classCount := dsmU02RequiredClassCount(raw)
	processed := "module=" + module + " min_length=" + dsmU02IntegerDisplay(minLen, hasMinLen) +
		" required_classes=" + strconv.Itoa(classCount)

	if module != "not_found" && hasMinLen && minLen >= 8 && classCount >= 3 {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: processed}
	}
	if module == "not_found" && !hasMinLen {
		return CheckResult{
			Status:           Manual,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "DSM UI or organization password-complexity policy must be verified",
		}
	}
	if (hasMinLen && minLen > 0 && minLen < 8) || (module != "not_found" && classCount > 0 && classCount < 3) {
		return CheckResult{
			Status:           Vulnerable,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "observed password complexity is below the baseline",
		}
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  processed,
		VulnerableConfig: "available settings do not establish the authoritative DSM and organization policy",
	}
}

func dsmU02JoinEvidence(files []FileResult) string {
	var parts []string
	for _, file := range files {
		parts = append(parts, "# FILE: "+file.Path+"\n"+file.Content)
	}
	return strings.Join(parts, "\n")
}

func dsmU02LastIntegerOption(raw string, keys ...string) (int, bool) {
	var found int
	ok := false
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripUnquotedComment(rawLine))
		fields := strings.Fields(strings.NewReplacer("=", " ", "\t", " ").Replace(line))
		for index := 0; index+1 < len(fields); index++ {
			for _, key := range keys {
				if strings.EqualFold(fields[index], key) {
					value, err := strconv.Atoi(strings.Trim(fields[index+1], `"'`))
					if err == nil {
						found, ok = value, true
					}
				}
			}
		}
	}
	return found, ok
}

func dsmU02RequiredClassCount(raw string) int {
	count := 0
	for _, key := range []string{"ucredit", "lcredit", "dcredit", "ocredit"} {
		value, ok := dsmU02LastIntegerOption(raw, key)
		if ok && value < 0 {
			count++
		}
	}
	return count
}

func dsmU02IntegerDisplay(value int, ok bool) string {
	if !ok {
		return "unspecified"
	}
	return strconv.Itoa(value)
}
