package main

import (
	"strings"
)

type U03Input struct {
	SystemAuth string
}

func checkU03(ctx ScanContext) CheckResult {
	const code = "U-03"
	const description = "Account lockout thresholds should be configured to limit brute-force sign-in attempts."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1110"}, // Brute Force
		mitigations: []string{"M1036"}, // Account Use Policies
	}

	input, errs := loadU03Input()

	result := evalU03(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU03Input() (U03Input, []string) {
	files, errs := collectFiles("/etc/pam.d/system-auth")
	if len(files) == 0 {
		return U03Input{}, errs
	}
	return U03Input{SystemAuth: files[0].Content}, errs
}

func evalU03(input U03Input) CheckResult {
	systemAuth := input.SystemAuth
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
	vulnerableConfig := ""
	if lockModule != "NOT_FOUND" && denyValue != "NOT_FOUND" && safeAtoi(denyValue) > 0 && safeAtoi(denyValue) <= 10 {
		result = StatusGood
	} else {
		reasons := []string{}
		if lockModule == "NOT_FOUND" {
			reasons = append(reasons, "문제점1. 계정 잠금 PAM 모듈이 설정되어 있지 않습니다.")
		}
		if denyValue == "NOT_FOUND" {
			reasons = append(reasons, "문제점2. deny 값이 설정되어 있지 않습니다.")
		} else if safeAtoi(denyValue) <= 0 || safeAtoi(denyValue) > 10 {
			reasons = append(reasons, "문제점2. deny 값이 10회 이하로 설정되어 있지 않습니다.")
		}
		vulnerableConfig = buildVulnerableConfig(
			"module="+lockModule,
			"deny="+denyValue,
			"unlock_time="+unlockValue,
			strings.Join(reasons, "\n"),
		)
	}

	faillogOutput := run("faillog -a")
	pamTallyOutput := run("pam_tally2 -u root")

	return CheckResult{
		Status:           result,
		RawConfig:        systemAuth + "\n" + faillogOutput + "\n" + pamTallyOutput,
		ProcessedConfig:  buildProcessedConfig("module="+lockModule, "deny="+denyValue, "unlock_time="+unlockValue),
		VulnerableConfig: vulnerableConfig,
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
