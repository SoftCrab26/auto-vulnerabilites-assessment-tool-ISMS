package main

import "strings"

type U46Input struct {
	Mail       Service
	SendmailCF string
	Found      bool
}

func checkU46(ctx ScanContext) CheckResult {
	input, errs := loadU46Input(ctx)
	result := evalU46(input)
	result.Code = "U-46"
	result.Description = "Restrict ordinary users from running the mail queue."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU46Input(ctx ScanContext) (U46Input, []string) {
	file, errs := collectFirstExisting("/etc/mail/sendmail.cf", "/etc/sendmail.cf")
	return U46Input{Mail: ctx.Services["mail"], SendmailCF: file.Content, Found: file.Path != ""}, errs
}

func evalU46(input U46Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.SendmailCF) == "" {
		return missingServiceConfig(input.Mail, "sendmail.cf")
	}
	privacy := sendmailPrivacyOptions(input.SendmailCF)
	restricted := optionPresent(privacy, "restrictqrun")
	result := CheckResult{Status: StatusGood, RawConfig: input.SendmailCF, ProcessedConfig: "privacy_options=" + strings.Join(privacy, ",")}
	if !restricted {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "PrivacyOptions does not include restrictqrun."
	}
	return result
}

func activeConfigText(raw string) string {
	var lines []string
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, strings.ToLower(line))
	}
	return strings.Join(lines, "\n")
}

func sendmailPrivacyOptions(raw string) []string {
	var options []string
	for _, line := range strings.Split(activeConfigText(raw), "\n") {
		index := strings.Index(line, "privacyoptions")
		if index < 0 {
			continue
		}
		value := strings.TrimSpace(strings.TrimLeft(line[index+len("privacyoptions"):], " \t=:"))
		options = append(options, strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })...)
	}
	return options
}

func optionPresent(options []string, target string) bool {
	for _, option := range options {
		if strings.EqualFold(option, target) {
			return true
		}
	}
	return false
}

func missingServiceConfig(service Service, name string) CheckResult {
	if service.IsActive() {
		return CheckResult{Status: StatusError, RawConfig: formatServiceStatus(service), ProcessedConfig: name + "=unavailable"}
	}
	return CheckResult{Status: StatusNotApplicable, RawConfig: formatServiceStatus(service), ProcessedConfig: name + "=not_applicable"}
}
