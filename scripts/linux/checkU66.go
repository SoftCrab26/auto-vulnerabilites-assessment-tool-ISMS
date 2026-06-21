package main

import (
	"strings"
)

type U66Input struct {
	RsyslogConf string
}

func checkU66(ctx ScanContext) CheckResult {
	const code = "U-66"
	const description = "System logging should be configured according to security policy."
	mitreAttack := MitreAttack{
		tactic:      "Defense Evasion",
		techniques:  []string{"T1562"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU66Input()

	result := evalU66(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU66Input() (U66Input, []string) {
	files, errs := collectFiles("/etc/rsyslog.conf")
	dropinConf := run("cat /etc/rsyslog.d/*.conf 2>/dev/null")

	if len(files) == 0 && strings.TrimSpace(dropinConf) == "" {
		return U66Input{}, errs
	}

	content := ""
	if len(files) > 0 {
		content = files[0].Content
	}
	if strings.TrimSpace(dropinConf) != "" {
		content += "\n" + dropinConf
	}

	return U66Input{RsyslogConf: content}, errs
}

func evalU66(input U66Input) CheckResult {
	content := input.RsyslogConf
	hasLogging := strings.Contains(content, "*.info") || strings.Contains(content, "auth") || strings.Contains(content, "kern") || strings.Contains(content, "mail")

	status := StatusGood
	vulnerableConfig := ""
	if !hasLogging {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"syslog_policy=NOT_FOUND",
			"문제점1. 보안 정책에 따른 시스템 로깅 설정이 되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("logging_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
