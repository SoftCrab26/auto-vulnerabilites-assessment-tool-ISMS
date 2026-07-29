package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU57Input struct {
	FTPActive bool
	FTPUsers  string
	Found     bool
}

func checkU57(ctx ScanContext) CheckResult {
	input, errs := loadU57Input(ctx)
	result := evalU57(input)
	result.Code = "U-57"
	result.Description = "root 계정을 FTP 로그인 거부 목록에 등록해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU57Input(ctx ScanContext) (DSMU57Input, []string) {
	if !dsmU57FTPActive(ctx) {
		return DSMU57Input{}, nil
	}
	paths := []string{
		"/etc/ftpusers",
		"/etc.defaults/ftpusers",
		"/usr/syno/etc/ftpusers",
		"/etc/vsftpd/ftpusers",
		"/etc/vsftpd/user_list",
		"/usr/syno/etc/vsftpd/ftpusers",
		"/usr/syno/etc/vsftpd/user_list",
	}
	var evidence []string
	for _, path := range paths {
		content, ok, err := dsmU57ReadBounded(path)
		if err != nil {
			return DSMU57Input{FTPActive: true, FTPUsers: strings.Join(evidence, "\n\n")}, []string{err.Error()}
		}
		if ok {
			evidence = append(evidence, "### "+path+"\n"+content)
		}
	}
	if len(evidence) == 0 {
		return DSMU57Input{FTPActive: true}, []string{"활성 FTP 서비스의 ftpusers/user_list를 찾을 수 없습니다"}
	}
	return DSMU57Input{FTPActive: true, FTPUsers: strings.Join(evidence, "\n\n"), Found: true}, nil
}

func evalU57(input DSMU57Input) CheckResult {
	if !input.FTPActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "ftp_service=inactive"}
	}
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: input.FTPUsers, ProcessedConfig: "ftp_root_deny=unknown", ErrMsg: "FTP 로그인 거부 목록을 확인할 수 없습니다"}
	}
	blocked := false
	for _, line := range strings.Split(input.FTPUsers, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "root" {
			blocked = true
			break
		}
	}
	if blocked {
		return CheckResult{Status: Good, RawConfig: input.FTPUsers, ProcessedConfig: "ftp_root_deny=enabled"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        input.FTPUsers,
		ProcessedConfig:  "ftp_root_deny=disabled",
		VulnerableConfig: "ftpusers 또는 deny 방식 user_list에 root 계정이 없습니다.",
	}
}

func dsmU57FTPActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") && service.IsActive {
			return true
		}
	}
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "proftpd", "vsftpd"}) || ports[20] || ports[21]
}

func dsmU57ReadBounded(path string) (string, bool, error) {
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
