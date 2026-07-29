package main

import "strings"

type U48Input struct {
	Mail       Service
	SendmailCF string
	Found      bool
}

func checkU48(ctx ScanContext) CheckResult {
	input, errs := loadU48Input(ctx)
	result := evalU48(input)
	result.Code = "U-48"
	result.Description = "Disable sendmail EXPN and VRFY commands."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU48Input(ctx ScanContext) (U48Input, []string) {
	file, errs := collectFirstExisting("/etc/mail/sendmail.cf", "/etc/sendmail.cf")
	return U48Input{Mail: ctx.Services["mail"], SendmailCF: file.Content, Found: file.Path != ""}, errs
}

func evalU48(input U48Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.SendmailCF) == "" {
		return missingServiceConfig(input.Mail, "sendmail.cf")
	}
	options := sendmailPrivacyOptions(input.SendmailCF)
	noexpn, novrfy := optionPresent(options, "noexpn"), optionPresent(options, "novrfy")
	result := CheckResult{Status: StatusGood, RawConfig: input.SendmailCF, ProcessedConfig: buildProcessedConfig("noexpn="+boolString(noexpn), "novrfy="+boolString(novrfy))}
	if !noexpn || !novrfy {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "PrivacyOptions must include both noexpn and novrfy."
	}
	return result
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
