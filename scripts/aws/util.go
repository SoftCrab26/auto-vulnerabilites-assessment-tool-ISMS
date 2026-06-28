package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

func joinErrors(errs []string) string {
	return strings.Join(errs, "\n")
}

func errorResult(code, guideCode, description string, mitre MitreAttack, errs []string) CheckResult {
	return CheckResult{
		Code:        code,
		GuideCode:   guideCode,
		Description: description,
		Status:      StatusError,
		ErrMsg:      joinErrors(errs),
		MitreAttack: mitre,
	}
}

func resultWithErrors(result CheckResult, errs []string) CheckResult {
	if len(errs) == 0 {
		return result
	}
	if result.ErrMsg == "" {
		result.ErrMsg = joinErrors(errs)
		return result
	}
	result.ErrMsg += "\n" + joinErrors(errs)
	return result
}

func safeAtoi(value string) int {
	i, _ := strconv.Atoi(value)
	return i
}

func buildProcessedConfig(parts ...string) string {
	return strings.Join(parts, " ")
}

func buildVulnerableConfig(parts ...string) string {
	return strings.Join(parts, "\n")
}

func compactJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var data any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return raw
	}

	encoded, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func isEmptyAWSOutput(raw string) bool {
	raw = strings.TrimSpace(raw)
	return raw == "" || raw == "[]" || raw == "{}" || raw == "null"
}

func appendUniqueError(errs []string, err string) []string {
	err = strings.TrimSpace(err)
	if err == "" {
		return errs
	}
	for _, existing := range errs {
		if existing == err {
			return errs
		}
	}
	return append(errs, err)
}

func checkAWSGeneric(code, guideCode, description string, mitre MitreAttack, result CheckResult) CheckResult {
	result.Code = code
	result.GuideCode = guideCode
	result.Description = description
	result.MitreAttack = mitre
	return result
}

func formatCount(count int) string {
	return strconv.Itoa(count)
}

func filterUsers(users []struct {
	UserName   string `json:"UserName"`
	Arn        string `json:"Arn"`
	CreateDate string `json:"CreateDate"`
}, predicate func(struct {
	UserName   string `json:"UserName"`
	Arn        string `json:"Arn"`
	CreateDate string `json:"CreateDate"`
}) bool) []struct {
	UserName   string `json:"UserName"`
	Arn        string `json:"Arn"`
	CreateDate string `json:"CreateDate"`
} {
	var result []struct {
		UserName   string `json:"UserName"`
		Arn        string `json:"Arn"`
		CreateDate string `json:"CreateDate"`
	}
	for _, user := range users {
		if predicate(user) {
			result = append(result, user)
		}
	}
	return result
}

func extractNames(users []struct {
	UserName   string `json:"UserName"`
	Arn        string `json:"Arn"`
	CreateDate string `json:"CreateDate"`
}) []string {
	var names []string
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}
