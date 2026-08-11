package main

import (
	"strings"
)

type U53Input struct {
	VsftpdConf string
}

func checkU53(ctx ScanContext) CheckResult {
	const code = "U-53"
	const description = "FTP banner should not expose unnecessary information."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU53Input()

	result := evalU53(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU53Input() (U53Input, []string) {
	files, errs := collectFiles("/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf")
	if len(files) == 0 {
		return U53Input{}, errs
	}
	return U53Input{VsftpdConf: files[0].Content}, errs
}

func evalU53(input U53Input) CheckResult {
	content := input.VsftpdConf
	hasBanner := strings.Contains(content, "ftpd_banner") || strings.Contains(content, "banner_file")

	status := StatusGood
	vulnerableConfig := ""
	if !hasBanner {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"ftpd_banner=NOT_SET",
			"문제점1. FTP 접속 배너에 정보가 노출될 수 있습니다. ftpd_banner 설정을 확인하세요.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("ftp_banner_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
