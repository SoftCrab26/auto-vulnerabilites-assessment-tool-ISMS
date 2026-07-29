package main

import "strings"

type U55Input struct {
	Passwd string
	Found  bool
}

func checkU55(ctx ScanContext) CheckResult {
	input, errs := loadU55Input(ctx)
	result := evalU55(input)
	result.Code = "U-55"
	result.Description = "FTP-related accounts should use restricted login shells."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU55Input(ctx ScanContext) (U55Input, []string) {
	_ = ctx
	file, errs := collectFirstExisting("/etc/passwd")
	return U55Input{Passwd: file.Content, Found: file.Path != ""}, errs
}

func evalU55(input U55Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: StatusError, ProcessedConfig: "passwd=unavailable"}
	}
	var bad []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 || !ftpLikeAccount(fields[0]) {
			continue
		}
		shell := strings.ToLower(strings.TrimSpace(fields[6]))
		if !strings.Contains(shell, "false") && !strings.Contains(shell, "nologin") {
			bad = append(bad, fields[0]+" shell="+fields[6])
		}
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.Passwd, ProcessedConfig: "ftp_account_shells=restricted"}
	if len(bad) > 0 {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "ftp_account_shells=interactive"
		result.VulnerableConfig = strings.Join(bad, "\n")
	}
	return result
}

func ftpLikeAccount(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "ftp" || name == "anonymous" || name == "guest" || strings.HasPrefix(name, "ftp")
}
