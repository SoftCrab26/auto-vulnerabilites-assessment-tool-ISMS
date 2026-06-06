package main

import (
	"strconv"
	"strings"
)

func checkU03() CheckResult {
	files, errs := collectFiles("/etc/pam.d/system-auth")

	if len(errs) > 0 {
		return CheckResult{
			Code:   "U-03",
			Status: StatusError,
			ErrMsg: strings.Join(errs, "; "),
		}
	}

	systemAuth := files[0].Content
	lockModule := "NOT_FOUND"
	denyValue := "NOT_FOUND"
	unlockValue := "NOT_FOUND"

	for _, line := range strings.Split(systemAuth, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "pam_faillock.so") || strings.Contains(line, "pam_tally2.so") {
			lockModule = "pam_faillock.so"
			if strings.Contains(line, "pam_tally2.so") {
				lockModule = "pam_tally2.so"
			}
			if deny := findOptionValue(line, "deny"); deny != "" {
				denyValue = deny
			}
			if unlock := findOptionValue(line, "unlock_time"); unlock != "" {
				unlockValue = unlock
			}
		}
	}

	result := StatusVulnerable

	if lockModule != "NOT_FOUND" {
		if denyValue != "NOT_FOUND" {
			if deny, err := strconv.Atoi(denyValue); err == nil && deny >= 5 {
				result = StatusGood
			}
		}
	}

	faillogOutput := run("faillog -a")
	pamTallyOutput := run("pam_tally2 -u root")

	return CheckResult{
		Code:        "U-03",
		Status:      result,
		Description: "Account lockout thresholds should be configured to limit brute-force sign-in attempts.",
		RawConfig:   systemAuth + "\n" + faillogOutput + "\n" + pamTallyOutput,
		ProcessedConfig: "module=" + lockModule +
			" deny=" + denyValue +
			" unlock_time=" + unlockValue,
		ErrMsg: strings.Join(errs, "; "),
	}
}

func findOptionValue(line string, option string) string {
	for _, part := range strings.Fields(line) {
		if strings.HasPrefix(part, option+"=") {
			return strings.TrimPrefix(part, option+"=")
		}
	}
	return ""
}
