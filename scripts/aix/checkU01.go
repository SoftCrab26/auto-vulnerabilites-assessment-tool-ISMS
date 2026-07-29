package main

import "strings"

type U01Input struct {
	SSHConfig    string
	SecurityUser string
	SSHService   Service
}

func checkU01(ctx ScanContext) CheckResult {
	input, errs := loadU01Input(ctx)
	result := evalU01(input)
	result.Code = "U-01"
	result.Description = "Direct remote root login must be disabled."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078.002", "T1133"}, Mitigations: []string{"M1042"}}
	return resultWithErrors(result, errs)
}

func loadU01Input(ctx ScanContext) (U01Input, []string) {
	files, errs := collectFiles("/etc/ssh/sshd_config", "/etc/security/user")
	input := U01Input{SSHService: ctx.Services["ssh"]}
	for _, file := range files {
		switch file.Path {
		case "/etc/ssh/sshd_config":
			input.SSHConfig = file.Content
		case "/etc/security/user":
			input.SecurityUser = file.Content
		}
	}
	return input, errs
}

func evalU01(input U01Input) CheckResult {
	permit := findConfigValue(input.SSHConfig, "PermitRootLogin")
	rlogin := findStanzaValue(input.SecurityUser, "root", "rlogin")
	status := StatusGood
	var problems []string
	if input.SSHConfig == "" || input.SecurityUser == "" {
		status = StatusError
		problems = append(problems, "required SSH or /etc/security/user input is missing")
	} else {
		if !strings.EqualFold(permit, "no") {
			status = StatusVulnerable
			problems = append(problems, "PermitRootLogin must be no")
		}
		if !strings.EqualFold(rlogin, "false") {
			status = StatusVulnerable
			problems = append(problems, "root rlogin must be false")
		}
	}
	return CheckResult{
		Status: status, RawConfig: "[sshd_config]\n" + input.SSHConfig + "\n[/etc/security/user root]\n" + extractStanza(input.SecurityUser, "root"),
		ProcessedConfig:  buildProcessedConfig("PermitRootLogin="+permit, "root.rlogin="+rlogin),
		VulnerableConfig: strings.Join(problems, "\n"),
	}
}
