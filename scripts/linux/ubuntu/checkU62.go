package main

import (
	"strings"
)

type U62Input struct {
	Paths []string
}

func checkU62(ctx ScanContext) CheckResult {
	const code = "U-62"
	const description = "Login warning banner should be set for SSH, Telnet, FTP, etc."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU62Input()

	result := evalU62(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU62Input() (U62Input, []string) {
	paths := []string{
		"/etc/issue",
		"/etc/issue.net",
		"/etc/motd",
		"/etc/ssh/sshd_config",
	}
	files, errs := collectFiles(paths...)
	var combined strings.Builder
	for _, f := range files {
		combined.WriteString("# " + f.Path + "\n" + f.Content + "\n")
	}
	return U62Input{Paths: paths}, errs // we don't really need Paths in struct but ok
}

func evalU62(input U62Input) CheckResult {
	// Re-collect for simplicity
	files, _ := collectFiles("/etc/issue", "/etc/issue.net", "/etc/motd", "/etc/ssh/sshd_config")
	var combined strings.Builder
	for _, f := range files {
		combined.WriteString(f.Content + "\n")
	}
	content := combined.String()

	hasBanner := strings.Contains(content, "Authorized") || strings.Contains(content, "WARNING") || strings.Contains(content, "login") || len(strings.TrimSpace(content)) > 20

	status := StatusGood
	vulnerableConfig := ""
	if !hasBanner {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"login_banner=NOT_FOUND",
			"문제점1. 로그인 시 경고 메시지(banner)가 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("banner_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
