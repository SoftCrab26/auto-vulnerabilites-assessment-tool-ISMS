package main

import (
	"encoding/json"
	"fmt"
)

type PasswordPolicy struct {
	PasswordPolicy struct {
		MinimumPasswordLength      int  `json:"MinimumPasswordLength"`
		RequireSymbols             bool `json:"RequireSymbols"`
		RequireNumbers             bool `json:"RequireNumbers"`
		RequireUppercaseCharacters bool `json:"RequireUppercaseCharacters"`
		RequireLowercaseCharacters bool `json:"RequireLowercaseCharacters"`
		AllowUsersToChangePassword bool `json:"AllowUsersToChangePassword"`
		ExpirePasswords            bool `json:"ExpirePasswords"`
		MaxPasswordAge             int  `json:"MaxPasswordAge"`
		PasswordReusePrevention    int  `json:"PasswordReusePrevention"`
		HardExpiry                 bool `json:"HardExpiry"`
	} `json:"PasswordPolicy"`
}

func checkAWS10(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-10", "1.10", "AWS 계정 패스워드 정책 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078.001"}, mitigations: []string{"M1027"}}

	result := evalAWS10(ctx.Runtime.PasswordPolicy)
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}

func evalAWS10(raw string) CheckResult {
	if isEmptyAWSOutput(raw) {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: buildProcessedConfig("no_policy_set"), VulnerableConfig: buildVulnerableConfig("문제점1: 패스워드 정책 미설정")}
	}

	var policy PasswordPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return CheckResult{Status: StatusManual, RawConfig: raw, ProcessedConfig: buildProcessedConfig("parse_error"), VulnerableConfig: "패스워드 정책 파싱 실패"}
	}

	pp := policy.PasswordPolicy
	violations := validatePasswordPolicy(pp)
	processedConfig := buildProcessedConfig(
		fmt.Sprintf("minLength=%d", pp.MinimumPasswordLength),
		fmt.Sprintf("requireSymbols=%v", pp.RequireSymbols),
		fmt.Sprintf("requireNumbers=%v", pp.RequireNumbers),
		fmt.Sprintf("reusePrevent=%d", pp.PasswordReusePrevention),
	)

	if len(violations) > 0 {
		vulnParts := append([]string{"문제점1: 패스워드 정책 기준 미달"}, violations...)
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: processedConfig, VulnerableConfig: buildVulnerableConfig(vulnParts...)}
	}

	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: processedConfig}
}

func validatePasswordPolicy(pp struct {
	MinimumPasswordLength      int
	RequireSymbols             bool
	RequireNumbers             bool
	RequireUppercaseCharacters bool
	RequireLowercaseCharacters bool
	AllowUsersToChangePassword bool
	ExpirePasswords            bool
	MaxPasswordAge             int
	PasswordReusePrevention    int
	HardExpiry                 bool
}) []string {
	var violations []string
	if pp.MinimumPasswordLength < 8 {
		violations = append(violations, fmt.Sprintf("최소 길이 미달 (현재: %d, 권장: 8)", pp.MinimumPasswordLength))
	}
	if !pp.RequireSymbols {
		violations = append(violations, "특수문자 요구 미설정")
	}
	if !pp.RequireNumbers {
		violations = append(violations, "숫자 요구 미설정")
	}
	if !pp.RequireUppercaseCharacters {
		violations = append(violations, "대문자 요구 미설정")
	}
	if !pp.RequireLowercaseCharacters {
		violations = append(violations, "소문자 요구 미설정")
	}
	if !pp.ExpirePasswords {
		violations = append(violations, "패스워드 만료 미설정")
	}
	if pp.PasswordReusePrevention < 5 {
		violations = append(violations, fmt.Sprintf("재사용 제한 미달 (현재: %d, 권장: 5)", pp.PasswordReusePrevention))
	}
	return violations
}
