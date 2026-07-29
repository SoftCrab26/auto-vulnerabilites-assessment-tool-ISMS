package main

import "strings"

type U53Input struct {
	FTP       Service
	FTPConfig string
	Found     bool
}

func checkU53(ctx ScanContext) CheckResult {
	input, errs := loadU53Input(ctx)
	result := evalU53(input)
	result.Code = "U-53"
	result.Description = "Configure an FTP banner that does not expose system information."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU53Input(ctx ScanContext) (U53Input, []string) {
	file, errs := collectFirstExisting("/etc/ftpaccess", "/etc/ftpd.cnf")
	return U53Input{FTP: ctx.Services["ftp"], FTPConfig: file.Content, Found: file.Path != ""}, errs
}

func evalU53(input U53Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.FTPConfig) == "" {
		return missingServiceConfig(input.FTP, "ftpaccess_or_ftpd.cnf")
	}
	content := activeConfigText(input.FTPConfig)
	hasBanner := false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "banner" || fields[0] == "greeting" || fields[0] == "message") {
			hasBanner = true
			break
		}
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.FTPConfig, ProcessedConfig: "ftp_banner=configured"}
	if !hasBanner {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "ftp_banner=missing"
		result.VulnerableConfig = "No FTP banner directive was found in ftpaccess or ftpd.cnf."
	}
	return result
}
