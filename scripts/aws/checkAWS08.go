package main

import (
	"fmt"
	"strings"
	"time"
)

func checkAWS08(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-08", "1.8", "Admin Console 계정 Access Key 활성화 및 사용주기 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078.001"}, mitigations: []string{"M1017"}}

	result := evalAWS08(ctx.Runtime.CredentialReport)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS08(raw string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("no_credential_report"), VulnerableConfig: "Credential Report를 수집할 수 없음"}
	}

	rootKey, oldKeys := analyzeCredentialReport(raw)
	isVulnerable := rootKey || oldKeys > 0
	processedConfig := buildProcessedConfig(fmt.Sprintf("root_access_key_exists=%v", rootKey), fmt.Sprintf("old_keys_90d=%d", oldKeys))

	if isVulnerable {
		vulnParts := []string{"문제점1: Access Key 관리 미흡"}
		if rootKey {
			vulnParts = append(vulnParts, "- Root 계정에 Access Key 존재")
		}
		if oldKeys > 0 {
			vulnParts = append(vulnParts, fmt.Sprintf("- 90일 이상 미갱신 Access Key %d개 존재", oldKeys))
		}
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: buildVulnerableConfig(vulnParts...)}
	}

	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: processedConfig}
}

func analyzeCredentialReport(raw string) (bool, int) {
	rootKey := false
	oldKeys := 0
	for i, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 10 {
			continue
		}
		if strings.TrimSpace(fields[0]) == "<root_account>" && strings.TrimSpace(fields[3]) == "true" {
			rootKey = true
		}
		if strings.TrimSpace(fields[3]) == "true" && isOlderThan90Days(strings.TrimSpace(fields[9])) {
			oldKeys++
		}
	}
	return rootKey, oldKeys
}

func isOlderThan90Days(dateStr string) bool {
	if dateStr == "" || dateStr == "N/A" {
		return false
	}
	lastUsed, err := time.Parse("2006-01-02T15:04:05Z", dateStr)
	if err != nil {
		return false
	}
	return time.Since(lastUsed).Hours()/24 > 90
}
