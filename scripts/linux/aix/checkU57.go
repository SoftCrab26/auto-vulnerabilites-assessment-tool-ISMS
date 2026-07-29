package main

import "strings"

type U57Input struct {
	FTP      Service
	FTPUsers string
	Found    bool
}

func checkU57(ctx ScanContext) CheckResult {
	input, errs := loadU57Input(ctx)
	result := evalU57(input)
	result.Code = "U-57"
	result.Description = "Block root from FTP login in /etc/ftpusers."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU57Input(ctx ScanContext) (U57Input, []string) {
	file, errs := collectFirstExisting("/etc/ftpusers")
	return U57Input{FTP: ctx.Services["ftp"], FTPUsers: file.Content, Found: file.Path != ""}, errs
}

func evalU57(input U57Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.FTPUsers) == "" {
		return missingServiceConfig(input.FTP, "ftpusers")
	}
	rootBlocked := false
	for _, rawLine := range strings.Split(input.FTPUsers, "\n") {
		line := strings.TrimSpace(rawLine)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Fields(line)[0] == "root" {
			rootBlocked = true
			break
		}
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.FTPUsers, ProcessedConfig: "root_in_ftpusers=" + boolString(rootBlocked)}
	if !rootBlocked {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "root is not listed in /etc/ftpusers."
	}
	return result
}
