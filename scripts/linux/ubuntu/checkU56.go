package main

import (
	"strings"
)

type U56Input struct {
	VsftpdConf string
}

func checkU56(ctx ScanContext) CheckResult {
	const code = "U-56"
	const description = "FTP access control should be configured (e.g. tcp_wrappers or vsftpd config)."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU56Input()

	result := evalU56(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU56Input() (U56Input, []string) {
	files, errs := collectFiles("/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf")
	if len(files) == 0 {
		return U56Input{}, errs
	}
	return U56Input{VsftpdConf: files[0].Content}, errs
}

func evalU56(input U56Input) CheckResult {
	content := input.VsftpdConf
	hasAccessControl := strings.Contains(content, "tcp_wrappers") || strings.Contains(content, "hosts_allow") || strings.Contains(content, "allow_writeable_chroot")

	status := StatusGood
	vulnerableConfig := ""
	if !hasAccessControl {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"ftp_access_control=NOT_FOUND",
			"문제점1. FTP 서비스에 접근 제어 설정이 적용되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("ftp_access_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
