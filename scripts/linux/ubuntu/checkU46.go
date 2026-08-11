package main

import (
	"strings"
)

type U46Input struct {
	SendmailMC string
}

func checkU46(ctx ScanContext) CheckResult {
	const code = "U-46"
	const description = "일반 사용자의 메일 서비스 실행을 제한해야 합니다."
	mitreAttack := MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548"},
		Mitigations: []string{"M1026"},
	}

	input, errs := loadU46Input()

	result := evalU46(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU46Input() (U46Input, []string) {
	files, errs := collectFiles("/etc/mail/sendmail.mc", "/etc/postfix/main.cf")
	if len(files) == 0 {
		return U46Input{}, errs
	}
	return U46Input{SendmailMC: files[0].Content}, errs
}

func evalU46(input U46Input) CheckResult {
	content := input.SendmailMC
	restricted := strings.Contains(content, "Restrict") || strings.Contains(content, "noexpn")

	status := StatusGood
	vulnerableConfig := ""
	if !restricted && strings.TrimSpace(content) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"mail_restrict=NOT_FOUND",
			"문제점1. 일반 사용자의 메일 서비스 실행이 제한되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("mail_restrict_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
