package main

import (
	"strings"
)

type U47Input struct {
	SendmailMC string
}

func checkU47(ctx ScanContext) CheckResult {
	const code = "U-47"
	const description = "스팸 메일 릴레이를 제한해야 합니다."
	mitreAttack := MitreAttack{
		Tactic:      "Impact",
		Techniques:  []string{"T1566"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU47Input()

	result := evalU47(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU47Input() (U47Input, []string) {
	files, errs := collectFiles("/etc/mail/sendmail.mc", "/etc/postfix/main.cf")
	if len(files) == 0 {
		return U47Input{}, errs
	}
	return U47Input{SendmailMC: files[0].Content}, errs
}

func evalU47(input U47Input) CheckResult {
	content := input.SendmailMC
	hasRelayControl := strings.Contains(content, "RELAY") || strings.Contains(content, "mynetworks")

	status := StatusGood
	vulnerableConfig := ""
	if !hasRelayControl && strings.TrimSpace(content) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"mail_relay=NOT_RESTRICTED",
			"문제점1. 스팸 메일 릴레이 제한이 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("mail_relay_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
