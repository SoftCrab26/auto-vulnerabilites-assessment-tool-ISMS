package main

import "strings"

type U47Input struct {
	Mail       Service
	SendmailCF string
	Found      bool
}

func checkU47(ctx ScanContext) CheckResult {
	input, errs := loadU47Input(ctx)
	result := evalU47(input)
	result.Code = "U-47"
	result.Description = "Restrict unauthorized mail relay."
	result.MitreAttack = MitreAttack{Tactic: "Impact", Techniques: []string{"T1566"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU47Input(ctx ScanContext) (U47Input, []string) {
	file, errs := collectFirstExisting("/etc/mail/sendmail.cf", "/etc/sendmail.cf")
	return U47Input{Mail: ctx.Services["mail"], SendmailCF: file.Content, Found: file.Path != ""}, errs
}

func evalU47(input U47Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.SendmailCF) == "" {
		return missingServiceConfig(input.Mail, "sendmail.cf")
	}
	content := activeConfigText(input.SendmailCF)
	hasAccessMap := strings.Contains(content, "kaccess ") || strings.Contains(content, "access_db") || strings.Contains(content, "/etc/mail/access")
	hasRelayRules := strings.Contains(content, "check_rcpt") || strings.Contains(content, "relay-domains") || strings.Contains(content, "relaying denied")
	restricted := hasAccessMap || hasRelayRules
	result := CheckResult{Status: StatusGood, RawConfig: input.SendmailCF, ProcessedConfig: "mail_relay_restricted=true"}
	if !restricted {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "mail_relay_restricted=false"
		result.VulnerableConfig = "No sendmail relay or access restriction was found."
	}
	return result
}
