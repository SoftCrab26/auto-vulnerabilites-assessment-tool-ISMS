package main

import (
	"fmt"
	"strings"
)

func checkAWS09(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-09", "1.9", "MFA (Multi-Factor Authentication) 설정"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1032"}}

	result := evalAWS09(ctx.Runtime.CredentialReport)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS09(raw string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("no_credential_report"), VulnerableConfig: "Credential Report를 수집할 수 없음"}
	}

	rootMFA, totalUsers, usersWithoutMFA := analyzeMFAStatus(raw)
	isVulnerable := !rootMFA || usersWithoutMFA > 0
	processedConfig := buildProcessedConfig(fmt.Sprintf("root_mfa=%v", rootMFA), fmt.Sprintf("total_users=%d", totalUsers), fmt.Sprintf("users_without_mfa=%d", usersWithoutMFA))

	if isVulnerable {
		vulnParts := []string{"문제점1: MFA 미설정 계정 존재"}
		if !rootMFA {
			vulnParts = append(vulnParts, "- Root 계정 MFA 미활성화")
		}
		if usersWithoutMFA > 0 {
			vulnParts = append(vulnParts, fmt.Sprintf("- IAM 사용자 중 %d명 MFA 미설정", usersWithoutMFA))
		}
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: buildVulnerableConfig(vulnParts...)}
	}

	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: processedConfig}
}

func analyzeMFAStatus(raw string) (bool, int, int) {
	rootMFA := false
	totalUsers := 0
	usersWithoutMFA := 0

	for i, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 8 {
			continue
		}

		username := strings.TrimSpace(fields[0])
		mfaActive := strings.TrimSpace(fields[7])

		if username == "<root_account>" {
			rootMFA = mfaActive == "true"
		} else if username != "N/A" {
			totalUsers++
			if mfaActive != "true" {
				usersWithoutMFA++
			}
		}
	}
	return rootMFA, totalUsers, usersWithoutMFA
}
