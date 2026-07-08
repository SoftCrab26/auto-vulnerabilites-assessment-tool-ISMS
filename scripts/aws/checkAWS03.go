package main

import (
	"encoding/json"
	"fmt"
)

func checkAWS03(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-03", "1.3", "IAM 사용자 계정 식별 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := evalAWS03(ctx.Runtime.IAMUsers)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS03(raw string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: buildProcessedConfig("no_users=true")}
	}

	var userList IAMUserList
	if err := json.Unmarshal([]byte(raw), &userList); err != nil {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("parse_error=true"), VulnerableConfig: "사용자 태그 정보 파싱 실패"}
	}

	untaggedUsers := filterUsers(userList.Users, func(u struct {
		UserName   string `json:"UserName"`
		Arn        string `json:"Arn"`
		CreateDate string `json:"CreateDate"`
	}) bool {
		return true
	})

	taggedCount := len(userList.Users) - len(untaggedUsers)
	processedConfig := buildProcessedConfig(fmt.Sprintf("total_users=%d", len(userList.Users)), fmt.Sprintf("tagged_users=%d", taggedCount))

	if len(untaggedUsers) == 0 {
		return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: processedConfig}
	}

	vulnConfig := buildVulnerableConfig("문제점1: 태그 미설정 IAM 사용자 존재", fmt.Sprintf("untagged_users: %d", len(untaggedUsers)))
	return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: vulnConfig}
}
