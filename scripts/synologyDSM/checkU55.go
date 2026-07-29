package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU55Input struct {
	FTPActive bool
	Passwd    string
	Found     bool
}

func checkU55(ctx ScanContext) CheckResult {
	input, errs := loadU55Input(ctx)
	result := evalU55(input)
	result.Code = "U-55"
	result.Description = "FTP 전용 계정에 로그인 불가 쉘을 지정해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU55Input(ctx ScanContext) (DSMU55Input, []string) {
	if !dsmU55FTPActive(ctx) {
		return DSMU55Input{}, nil
	}
	content, ok, err := dsmU55ReadBounded("/etc/passwd")
	if err != nil {
		return DSMU55Input{FTPActive: true}, []string{err.Error()}
	}
	if !ok {
		return DSMU55Input{FTPActive: true}, []string{"/etc/passwd를 찾을 수 없습니다"}
	}
	return DSMU55Input{FTPActive: true, Passwd: content, Found: true}, nil
}

func evalU55(input DSMU55Input) CheckResult {
	if !input.FTPActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "ftp_service=inactive"}
	}
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: input.Passwd, ProcessedConfig: "ftp_account_shell=unknown", ErrMsg: "/etc/passwd를 확인할 수 없습니다"}
	}
	var ftpAccounts, unsafe []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 || !dsmU55IsFTPAccount(fields[0]) {
			continue
		}
		ftpAccounts = append(ftpAccounts, line)
		shell := strings.TrimSpace(fields[6])
		if !dsmU55RestrictedShell(shell) {
			unsafe = append(unsafe, fields[0]+" shell="+shell)
		}
	}
	raw := strings.Join(ftpAccounts, "\n")
	if len(unsafe) == 0 {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "ftp_account_shell=restricted"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "ftp_account_shell=interactive",
		VulnerableConfig: strings.Join(unsafe, "\n"),
	}
}

func dsmU55IsFTPAccount(username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	return username == "ftp" || username == "ftpuser"
}

func dsmU55RestrictedShell(shell string) bool {
	shell = strings.ToLower(strings.TrimSpace(shell))
	return shell == "/bin/false" || shell == "/usr/bin/false" ||
		strings.HasSuffix(shell, "/nologin") || shell == "/dev/null"
}

func dsmU55FTPActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") && service.IsActive {
			return true
		}
	}
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "proftpd", "vsftpd"}) || ports[20] || ports[21]
}

func dsmU55ReadBounded(path string) (string, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > 2*1024*1024 {
		return "", false, fmt.Errorf("%s: file exceeds 2 MiB", path)
	}
	return string(data), true, nil
}
