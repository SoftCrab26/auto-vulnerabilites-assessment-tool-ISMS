package main

import (
	"encoding/json"
	"strings"
)

type IAMUserList struct {
	Users []struct {
		UserName   string `json:"UserName"`
		Arn        string `json:"Arn"`
		CreateDate string `json:"CreateDate"`
	} `json:"Users"`
}

func checkAWS01(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-01", "1.1", "사용자 계정 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := evalAWS01(ctx.Runtime.IAMUsers)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS01(raw string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{
			Status:           StatusManual,
			RawConfig:        raw,
			ProcessedConfig:  buildProcessedConfig("implementation=no_iam_users_found"),
			VulnerableConfig: "",
		}
	}

	var userList IAMUserList
	if err := json.Unmarshal([]byte(raw), &userList); err != nil {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("parse_error=true")}
	}

	adminUsers := filterUsers(userList.Users, func(u struct {
		UserName   string `json:"UserName"`
		Arn        string `json:"Arn"`
		CreateDate string `json:"CreateDate"`
	}) bool {
		return strings.Contains(strings.ToLower(u.Arn+u.UserName), "admin")
	})

	adminCount := len(adminUsers)
	processedConfig := buildProcessedConfig("total_users="+formatCount(len(userList.Users)), "admin_users="+formatCount(adminCount))

	vulnConfig := ""
	if adminCount > 1 {
		userNames := extractNames(adminUsers)
		vulnConfig = buildVulnerableConfig("문제점1: 관리자 권한을 보유한 다수 계정 존재", "admin_accounts: "+strings.Join(userNames, ", "))
	}

	return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: vulnConfig}
}
