package main

import "strings"

type U56Input struct {
	FTP          Service
	AccessConfig string
	Found        bool
}

func checkU56(ctx ScanContext) CheckResult {
	input, errs := loadU56Input(ctx)
	result := evalU56(input)
	result.Code = "U-56"
	result.Description = "Restrict FTP access by authorized hosts."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU56Input(ctx ScanContext) (U56Input, []string) {
	files, errs := collectFiles("/etc/ftpaccess", "/etc/ftpd.cnf", "/etc/hosts.allow", "/etc/hosts.deny")
	return U56Input{FTP: ctx.Services["ftp"], AccessConfig: buildLabeledRawConfig(files), Found: len(files) > 0}, errs
}

func evalU56(input U56Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.AccessConfig) == "" {
		return missingServiceConfig(input.FTP, "ftp_host_access")
	}
	content := activeConfigText(input.AccessConfig)
	restricted := false
	for _, marker := range []string{"ftp:", "ftpd:", "deny ", "allow ", "class ", "guestgroup ", "limit "} {
		if strings.Contains(content, marker) {
			restricted = true
			break
		}
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.AccessConfig, ProcessedConfig: "ftp_host_access=restricted"}
	if !restricted {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "ftp_host_access=unrestricted"
		result.VulnerableConfig = "No FTP host access restriction was found."
	}
	return result
}
