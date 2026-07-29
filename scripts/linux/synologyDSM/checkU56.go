package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type DSMU56Input struct {
	FTPActive    bool
	AccessConfig string
	Found        bool
}

func checkU56(ctx ScanContext) CheckResult {
	input, errs := loadU56Input(ctx)
	result := evalU56(input)
	result.Code = "U-56"
	result.Description = "FTP 접속을 허가된 호스트 또는 IP로 제한해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU56Input(ctx ScanContext) (DSMU56Input, []string) {
	if !dsmU56FTPActive(ctx) {
		return DSMU56Input{}, nil
	}
	paths := []string{
		"/etc/hosts.allow",
		"/etc/hosts.deny",
		"/usr/syno/etc/ftpd.conf",
		"/etc/ftpd.conf",
		"/etc.defaults/ftpd.conf",
		"/usr/syno/etc/proftpd.conf",
		"/etc/proftpd.conf",
		"/etc.defaults/proftpd.conf",
		"/etc/vsftpd.conf",
	}
	var evidence []string
	for _, path := range paths {
		content, ok, err := dsmU56ReadBounded(path)
		if err != nil {
			return DSMU56Input{FTPActive: true, AccessConfig: strings.Join(evidence, "\n\n")}, []string{err.Error()}
		}
		if ok {
			evidence = append(evidence, "### "+path+"\n"+content)
		}
	}
	if len(evidence) == 0 {
		return DSMU56Input{FTPActive: true}, []string{"활성 FTP 서비스의 호스트/IP 접근 제어 설정을 찾을 수 없습니다"}
	}
	return DSMU56Input{FTPActive: true, AccessConfig: strings.Join(evidence, "\n\n"), Found: true}, nil
}

func evalU56(input DSMU56Input) CheckResult {
	if !input.FTPActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "ftp_service=inactive"}
	}
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: input.AccessConfig, ProcessedConfig: "ftp_host_access=unknown", ErrMsg: "활성 FTP 서비스 접근 제어 설정을 확인할 수 없습니다"}
	}
	effective := strings.ToLower(dsmU56EffectiveConfig(input.AccessConfig))
	restricted := dsmU56HasSpecificAllow(effective) &&
		(strings.Contains(effective, "denyall") ||
			dsmU56HasDenyAll(effective) ||
			strings.Contains(effective, "tcp_wrappers=yes"))
	if restricted {
		return CheckResult{Status: Good, RawConfig: input.AccessConfig, ProcessedConfig: "ftp_host_access=restricted"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        input.AccessConfig,
		ProcessedConfig:  "ftp_host_access=unrestricted",
		VulnerableConfig: "FTP 기본 차단과 허가 호스트/IP 목록의 조합을 확인할 수 없습니다.",
	}
}

func dsmU56EffectiveConfig(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func dsmU56HasSpecificAllow(raw string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^(?:ftp|ftpd|proftpd|vsftpd)\s*:\s*([^\n]+)$`),
		regexp.MustCompile(`(?m)^allow\s+from\s+([^\n]+)$`),
		regexp.MustCompile(`(?m)^hosts_allow\s*=\s*([^\n]+)$`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(raw, -1) {
			value := strings.TrimSpace(match[1])
			if value != "" && value != "all" {
				return true
			}
		}
	}
	return false
}

func dsmU56HasDenyAll(raw string) bool {
	pattern := regexp.MustCompile(`(?m)^(?:all|ftp|ftpd|proftpd|vsftpd)\s*:\s*all(?:\s|$)`)
	return pattern.MatchString(raw)
}

func dsmU56FTPActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") && service.IsActive {
			return true
		}
	}
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "proftpd", "vsftpd"}) || ports[20] || ports[21]
}

func dsmU56ReadBounded(path string) (string, bool, error) {
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
