package main

import (
	"fmt"
	"strings"
)

type U62Input struct {
	Files []FileResult
}

func checkU62(ctx ScanContext) CheckResult {
	const code = "U-62"
	const description = "A warning banner should be configured for local and remote login."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1022"}}

	input, errs := loadU62Input()
	result := evalU62(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU62Input() (U62Input, []string) {
	files, errs := collectFiles(
		"/etc/security/login.cfg",
		"/etc/motd",
		"/etc/security/messages",
		"/etc/ssh/sshd_config",
	)
	if len(files) > 0 {
		errs = nil
	}
	return U62Input{Files: files}, errs
}

func evalU62(input U62Input) CheckResult {
	if len(input.Files) == 0 {
		return CheckResult{Status: StatusError, ProcessedConfig: "banner_sources=missing", ErrMsg: "no login banner source was readable"}
	}

	localBanner, messageBanner, sshBanner := false, false, false
	for _, file := range input.Files {
		switch file.Path {
		case "/etc/security/login.cfg":
			localBanner = configuredHerald(file.Content)
		case "/etc/motd", "/etc/security/messages":
			messageBanner = messageBanner || meaningfulBanner(file.Content)
		case "/etc/ssh/sshd_config":
			sshBanner = configuredSSHBanner(file.Content)
		}
	}

	status := StatusGood
	vulnerable := ""
	if !localBanner && !messageBanner && !sshBanner {
		status = StatusVulnerable
		vulnerable = "No login herald, message banner, or SSH Banner directive was found."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("readable_banner_sources=%d (banner text omitted)", len(input.Files)),
		ProcessedConfig:  fmt.Sprintf("login_herald=%t message_banner=%t ssh_banner=%t", localBanner, messageBanner, sshBanner),
		VulnerableConfig: vulnerable,
	}
}

func configuredHerald(config string) bool {
	for _, line := range activeConfigLines(config) {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "herald") {
			value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			return value != "" && !strings.EqualFold(value, "none")
		}
	}
	return false
}

func meaningfulBanner(config string) bool {
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "*") {
			return true
		}
	}
	return false
}

func configuredSSHBanner(config string) bool {
	for _, line := range activeConfigLines(config) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Banner") {
			return !strings.EqualFold(fields[1], "none") && fields[1] != ""
		}
	}
	return false
}
