package main

type W27Input struct {
	RawConfig string
}

func checkW27(ctx ScanContext) CheckResult {
	const code = "W-27"
	const description = "User Account Control should be enabled with an appropriate administrator prompt level."
	mitreAttack := MitreAttack{
		tactic:      "Privilege Escalation",
		techniques:  []string{"T1548.002"},
		mitigations: []string{"M1052"},
	}

	input, errs := loadW27Input(ctx)
	result := evalW27(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW27Input(ctx ScanContext) (W27Input, []string) {
	commands, errs := collectCommands(`$p=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue; "ENABLE_LUA=$(if($null -eq $p.EnableLUA){'NOT_FOUND'}else{$p.EnableLUA})"; "CONSENT_PROMPT_ADMIN=$(if($null -eq $p.ConsentPromptBehaviorAdmin){'NOT_FOUND'}else{$p.ConsentPromptBehaviorAdmin})"; "PROMPT_SECURE_DESKTOP=$(if($null -eq $p.PromptOnSecureDesktop){'NOT_FOUND'}else{$p.PromptOnSecureDesktop})"`)
	return W27Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW27(input W27Input) CheckResult {
	enableLUA := findConfigValue(input.RawConfig, "ENABLE_LUA")
	prompt := findConfigValue(input.RawConfig, "CONSENT_PROMPT_ADMIN")
	secureDesktop := findConfigValue(input.RawConfig, "PROMPT_SECURE_DESKTOP")
	status := StatusManual
	vulnerable := ""

	if enableLUA == "0" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("EnableLUA=0", "User Account Control is disabled.")
	} else if enableLUA == "1" {
		status = StatusInterview
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("enable_lua="+enableLUA, "consent_prompt_admin="+prompt, "secure_desktop="+secureDesktop),
		VulnerableConfig: vulnerable,
	}
}
