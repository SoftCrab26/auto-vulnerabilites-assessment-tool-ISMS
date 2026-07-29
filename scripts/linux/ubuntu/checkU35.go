package main

import (
	"strings"
)

type U35Input struct {
	VsftpdConf string
	SmbConf    string
}

func checkU35(ctx ScanContext) CheckResult {
	const code = "U-35"
	const description = "Anonymous access to shared services should be restricted."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU35Input()

	result := evalU35(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU35Input() (U35Input, []string) {
	paths := []string{
		"/etc/vsftpd/vsftpd.conf",
		"/etc/vsftpd.conf",
		"/etc/samba/smb.conf",
	}

	input := U35Input{}
	for _, path := range paths {
		files, _ := collectFiles(path)
		if len(files) == 0 {
			continue
		}

		switch path {
		case "/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf":
			input.VsftpdConf += files[0].Content + "\n"
		case "/etc/samba/smb.conf":
			input.SmbConf = files[0].Content
		}
	}

	return input, nil
}

func evalU35(input U35Input) CheckResult {
	var issues []string

	if isAnonymousEnabled(input.VsftpdConf, "anonymous_enable") {
		issues = append(issues, "vsftpd anonymous_enable=YES")
	}
	if isAnonymousEnabled(input.SmbConf, "guest ok") {
		issues = append(issues, "samba guest ok=YES")
	}
	if strings.Contains(strings.ToLower(input.SmbConf), "map to guest = bad user") {
		issues = append(issues, "samba map to guest=bad user")
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(issues) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(issues, "\n"),
			"문제점1. 공유 서비스에 익명 접근이 허용되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.VsftpdConf + input.SmbConf,
		ProcessedConfig:  buildProcessedConfig("anonymous_access_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}

func isAnonymousEnabled(content string, key string) bool {
	value := strings.ToLower(findConfigValue(content, key))
	return value == "yes" || value == "true" || value == "1"
}
