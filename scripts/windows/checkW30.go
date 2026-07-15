package main

import "strings"

type W30Input struct {
	Caption string
	Text    string
	Raw     string
}

func checkW30(ctx ScanContext) CheckResult {
	const code = "W-30"
	const description = "A legal notice caption and text should be configured for interactive logon."
	mitreAttack := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1036"}}

	input, errs := loadW30Input()
	result := evalW30(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW30Input() (W30Input, []string) {
	command := `$p=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Write-Output ('CAPTION=' + [string]$p.legalnoticecaption); Write-Output ('TEXT=' + [string]$p.legalnoticetext)`
	results, errs := collectCommands(command)
	raw := firstCommandOutput(results)
	return W30Input{Caption: findConfigValue(raw, "CAPTION"), Text: findConfigValue(raw, "TEXT"), Raw: raw}, errs
}

func evalW30(input W30Input) CheckResult {
	captionPresent := strings.TrimSpace(input.Caption) != "" && input.Caption != "NOT_FOUND"
	textPresent := strings.TrimSpace(input.Text) != "" && input.Text != "NOT_FOUND"
	status := StatusGood
	vulnerable := ""
	if !captionPresent || !textPresent {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("caption_present="+strings.ToLower(strconvFormatBool(captionPresent)), "text_present="+strings.ToLower(strconvFormatBool(textPresent)))
	}
	return CheckResult{Status: status, RawConfig: input.Raw, ProcessedConfig: buildProcessedConfig("caption_present="+strconvFormatBool(captionPresent), "text_present="+strconvFormatBool(textPresent)), VulnerableConfig: vulnerable}
}

func strconvFormatBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
