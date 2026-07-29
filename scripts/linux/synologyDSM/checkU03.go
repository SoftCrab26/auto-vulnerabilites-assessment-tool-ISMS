package main

import (
	"strconv"
	"strings"
)

type U03Input struct {
	Evidence []FileResult
}

func checkU03(ctx ScanContext) CheckResult {
	input, errs := loadU03Input(ctx)
	result := evalU03(input)
	result.Code = "U-03"
	result.Description = "Account lockout must limit repeated authentication failures."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1110"},
		Mitigations: []string{"M1036"},
	}
	return resultWithErrors(result, errs)
}

func loadU03Input(_ ScanContext) (U03Input, []string) {
	files, errs := collectFiles(
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/synoautoblock.conf",
		"/etc/synoinfo.conf",
		"/etc.defaults/synoinfo.conf",
	)
	return U03Input{Evidence: files}, errs
}

func evalU03(input U03Input) CheckResult {
	if len(input.Evidence) == 0 {
		return CheckResult{Status: Error, ErrMsg: "account lockout evidence is unavailable"}
	}
	raw := dsmU03JoinEvidence(input.Evidence)
	lower := strings.ToLower(raw)
	module := "not_found"
	if strings.Contains(lower, "pam_faillock.so") {
		module = "pam_faillock"
	} else if strings.Contains(lower, "pam_tally2.so") {
		module = "pam_tally2"
	}
	deny, hasDeny := dsmU03FindInteger(raw, "deny", "attempts", "max_attempts", "login_fail_max")
	processed := "module=" + module + " deny=" + dsmU03IntegerDisplay(deny, hasDeny)
	if hasDeny && deny >= 1 && deny <= 10 {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: processed}
	}
	if hasDeny && (deny <= 0 || deny > 10) {
		return CheckResult{
			Status:           Vulnerable,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "lockout threshold must be between 1 and 10 attempts",
		}
	}
	if module != "not_found" {
		return CheckResult{
			Status:           Manual,
			RawConfig:        raw,
			ProcessedConfig:  processed,
			VulnerableConfig: "lockout module exists, but its effective threshold is not evident",
		}
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  processed,
		VulnerableConfig: "verify the DSM Control Panel automatic-block policy",
	}
}

func dsmU03JoinEvidence(files []FileResult) string {
	var parts []string
	for _, file := range files {
		parts = append(parts, "# FILE: "+file.Path+"\n"+file.Content)
	}
	return strings.Join(parts, "\n")
}

func dsmU03FindInteger(raw string, keys ...string) (int, bool) {
	replacer := strings.NewReplacer("=", " ", "\t", " ", `"`, " ", "'", " ")
	for _, rawLine := range strings.Split(raw, "\n") {
		fields := strings.Fields(replacer.Replace(stripUnquotedComment(rawLine)))
		for index := 0; index+1 < len(fields); index++ {
			for _, key := range keys {
				if strings.EqualFold(fields[index], key) {
					value, err := strconv.Atoi(strings.Trim(fields[index+1], ",;"))
					if err == nil {
						return value, true
					}
				}
			}
		}
	}
	return 0, false
}

func dsmU03IntegerDisplay(value int, ok bool) string {
	if !ok {
		return "unspecified"
	}
	return strconv.Itoa(value)
}
