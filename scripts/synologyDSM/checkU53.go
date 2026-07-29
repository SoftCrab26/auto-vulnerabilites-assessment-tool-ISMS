package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU53Input struct {
	FTPActive  bool
	ConfigPath string
	FTPConfig  string
	Found      bool
}

func checkU53(ctx ScanContext) CheckResult {
	input, errs := loadU53Input(ctx)
	result := evalU53(input)
	result.Code = "U-53"
	result.Description = "FTP 배너에서 불필요한 시스템 정보를 노출하지 않아야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU53Input(ctx ScanContext) (DSMU53Input, []string) {
	if !dsmU53FTPActive(ctx) {
		return DSMU53Input{}, nil
	}
	paths := []string{
		"/usr/syno/etc/ftpd.conf",
		"/etc/ftpd.conf",
		"/etc.defaults/ftpd.conf",
		"/usr/syno/etc/proftpd.conf",
		"/etc/proftpd.conf",
		"/etc.defaults/proftpd.conf",
		"/etc/vsftpd.conf",
	}
	for _, path := range paths {
		content, ok, err := dsmU53ReadBounded(path)
		if err != nil {
			return DSMU53Input{FTPActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU53Input{FTPActive: true, ConfigPath: path, FTPConfig: content, Found: true}, nil
		}
	}
	return DSMU53Input{FTPActive: true}, []string{"활성 FTP 서비스 설정 파일을 찾을 수 없습니다"}
}

func evalU53(input DSMU53Input) CheckResult {
	if !input.FTPActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "ftp_service=inactive"}
	}
	raw := dsmU53Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "ftp_banner=unknown", ErrMsg: "활성 FTP 서비스 배너 설정을 확인할 수 없습니다"}
	}
	effective := strings.ToLower(dsmU53EffectiveConfig(input.FTPConfig))
	safe := strings.Contains(effective, "serverident off") ||
		strings.Contains(effective, "ftpd_banner=") ||
		strings.Contains(effective, "banner_file=") ||
		strings.Contains(effective, "displaylogin ")
	if safe {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "ftp_banner=restricted_or_custom"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "ftp_banner=default_or_exposed",
		VulnerableConfig: "기본 FTP 배너의 제품명/버전 노출을 제한하는 설정을 확인할 수 없습니다.",
	}
}

func dsmU53Raw(input DSMU53Input) string {
	if input.ConfigPath == "" {
		return input.FTPConfig
	}
	return input.ConfigPath + "\n" + input.FTPConfig
}

func dsmU53EffectiveConfig(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func dsmU53FTPActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") && service.IsActive {
			return true
		}
	}
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "proftpd", "vsftpd"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"FTP"}) ||
		ports[20] || ports[21]
}

func dsmU53ReadBounded(path string) (string, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > 256*1024 {
		return "", false, fmt.Errorf("%s: file exceeds 256 KiB", path)
	}
	return string(data), true, nil
}
