package main

import (
	"strconv"
	"strings"
)

type U06Input struct {
	SuPam string
}

func checkU06(ctx ScanContext) CheckResult {
	const code = "U-06"
	const description = "su command should be restricted to specific group (e.g. wheel group)."
	mitreAttack := MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548.003"},
		Mitigations: []string{"M1026"},
	}

	input, errs := loadU06Input()

	result := evalU06(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU06Input() (U06Input, []string) {
	files, errs := collectFiles("/etc/pam.d/su")
	if len(files) == 0 {
		return U06Input{}, errs
	}
	return U06Input{SuPam: files[0].Content}, errs
}

func evalU06(input U06Input) CheckResult {
	suContent := input.SuPam
	hasWheel := false

	for _, line := range strings.Split(suContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "pam_wheel.so") {
			hasWheel = true
			break
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if !hasWheel {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"pam_wheel=NOT_FOUND",
			"문제점1. /etc/pam.d/su 에 pam_wheel.so 설정이 없습니다. su 명령어 사용 제한이 적용되지 않았습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        suContent,
		ProcessedConfig:  buildProcessedConfig("pam_wheel_configured=" + strconv.FormatBool(hasWheel)),
		VulnerableConfig: vulnerableConfig,
	}
}

// boolToStr removed to avoid duplicate across files; use strconv.FormatBool instead
